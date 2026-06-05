"""
agent.py
========
The LLM tool-calling agent loop for the AI Pentesting / Recon Assistant.

This is the "brain" from the roadmap (Month 2): give it an authorized target,
and it autonomously decides which recon tools to run, reasons over the output,
and writes a first-draft security report.

It is vendor-neutral — pick the LLM with --provider:
    anthropic | openai | openrouter | gemini   (see llm.py)

How it works
------------
1. We hand the model a system prompt (a careful, scope-aware junior pentester)
   plus the JSON schemas for every tool in the registry.
2. The model replies. If it wants data, it emits one or more tool calls.
3. We execute each requested tool via the registry, feed the JSON result back as
   a tool result, and loop.
4. When the model stops asking for tools, its final text is the security report.

SAFETY: every wrapper enforces the scope allow-list at the code level, so even if
the model asks to scan something out of scope, the call is refused.

Usage
-----
    export ANTHROPIC_API_KEY=sk-...        # or OPENAI / OPENROUTER / GEMINI key
    python agent.py 127.0.0.1
    python agent.py 192.168.56.101 --provider gemini --scope 192.168.56.0/24
    python agent.py 10.0.0.5 --provider openrouter --model anthropic/claude-3.5-sonnet
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# The registry of the web/recon tools, plus the shared scope guard.
from tool_wrappers import TOOL_REGISTRY as _WEB_REGISTRY
from nmap_wrapper import (
    NMAP_TOOL_SCHEMA,
    DEFAULT_ALLOWED_SCOPE,
    ScopeError,
    run_nmap,
)
from llm import (
    DEFAULT_MODELS,
    PROVIDERS,
    LLMProvider,
    Turn,
    has_api_key,
    env_key_for,
    make_provider,
)


# ---------------------------------------------------------------------------
# Full tool registry: nmap + the web tools
# ---------------------------------------------------------------------------
# tool_wrappers.TOOL_REGISTRY deliberately leaves nmap out (it lives in its own
# module). The agent needs ALL of them, so we merge here: name -> (callable, schema).

TOOL_REGISTRY: dict[str, tuple[Callable[..., Any], dict]] = {
    "run_nmap": (run_nmap, NMAP_TOOL_SCHEMA),
    **_WEB_REGISTRY,
}


# ---------------------------------------------------------------------------
# System prompt — defines the agent's behaviour
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an autonomous junior penetration tester performing AUTHORIZED recon on a
single target. You have a set of recon/vuln tools available as functions.

Your job:
1. Start broad, then go deep. A sensible flow is: check the host is up, find open
   ports and service versions, probe any web services, fingerprint their tech,
   then run targeted vulnerability checks on what you actually found.
2. Only call a tool when its output will change what you do next. Do not run
   redundant scans.
3. Reason out loud briefly between tool calls about what you learned and why you
   are picking the next tool.
4. When you have enough evidence, STOP calling tools and write the final report.

Rules:
- Every target is restricted to an authorized scope enforced in code. If a tool
  returns a scope error, do NOT retry it — pick something in scope or report.
- Never invent findings. Base every finding on actual tool output.
- Prefer non-intrusive options. Do not request brute-force or exploit scripts.

Final report format (Markdown):
  # Security Report: <target>
  ## Summary               (2-3 sentences, overall risk)
  ## Findings              (one subsection per finding)
     - Severity: info|low|medium|high|critical
     - Evidence: the concrete tool output that proves it
     - Remediation: how to fix it
  ## Scan Log              (bullet list of the tools you ran and why)
"""


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

def _dispatch_tool(name: str, args: dict, allowed_scope: list[str]) -> str:
    """Run one tool from the registry and return its result as a JSON string.

    All exceptions are caught and returned as a JSON error so a single bad tool
    call can never crash the agent loop. The model reads the error and adapts.
    """
    entry = TOOL_REGISTRY.get(name)
    if entry is None:
        return json.dumps({"error": f"Unknown tool {name!r}."})

    func, _schema = entry
    if not isinstance(args, dict):
        return json.dumps({"error": f"Tool args must be an object, got {type(args).__name__}."})
    try:
        # Inject the run's scope into every wrapper (they all accept it kw-only).
        result = func(allowed_scope=allowed_scope, **args)
    except ScopeError as exc:
        return json.dumps({"error": f"ScopeError: {exc}"})
    except TypeError as exc:
        # Bad/missing arguments from the model.
        return json.dumps({"error": f"Bad arguments for {name}: {exc}"})
    except Exception as exc:  # pragma: no cover - defensive
        return json.dumps({"error": f"{name} crashed: {exc}"})

    # Wrappers return dataclasses with a to_json(); fall back to str otherwise.
    return result.to_json() if hasattr(result, "to_json") else json.dumps(str(result))


# ---------------------------------------------------------------------------
# The agent loop
# ---------------------------------------------------------------------------

@dataclass
class AgentRun:
    """The outcome of one autonomous recon run."""
    target: str
    provider: str = ""
    model: str = ""
    report: str = ""
    steps: int = 0
    tool_calls: list[dict] = field(default_factory=list)  # {name, input}
    tool_results: list[dict] = field(default_factory=list)  # {name, input, output}
    stopped_reason: str = ""


def run_agent(
    target: str,
    *,
    provider: str | LLMProvider = "anthropic",
    model: Optional[str] = None,
    allowed_scope: Optional[list[str]] = None,
    max_steps: int = 10,
    verbose: bool = True,
) -> AgentRun:
    """Drive an LLM through an autonomous recon of `target`.

    Parameters
    ----------
    target : str
        Host/IP/domain to recon. Must be inside `allowed_scope`.
    provider : str | LLMProvider
        Provider name ("anthropic", "openai", "openrouter", "gemini") or an
        already-built LLMProvider instance (handy for tests/mocks).
    model : str, optional
        Model id; defaults to the provider's default.
    allowed_scope : list[str], optional
        Scope allow-list passed to every tool. Defaults to localhost + private.
    max_steps : int
        Hard cap on tool-calling rounds, so the agent can't loop forever.
    verbose : bool
        Print reasoning + tool calls as they happen.
    """
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE

    if isinstance(provider, LLMProvider):
        prov = provider
        prov_name = prov.name
        model = getattr(prov, "model", model or "")
    else:
        prov_name = provider
        model = model or DEFAULT_MODELS.get(provider)
        prov = make_provider(provider, model)

    tools = [schema for (_func, schema) in TOOL_REGISTRY.values()]

    turns: list[Turn] = [Turn(
        role="user",
        text=(
            f"Target: {target}\n"
            f"Authorized scope: {allowed_scope}\n\n"
            "Perform autonomous recon and produce the security report."
        ),
    )]

    run = AgentRun(target=target, provider=prov_name, model=model or "")

    for step in range(1, max_steps + 1):
        run.steps = step
        reply = prov.chat(
            system=SYSTEM_PROMPT,
            tools=tools,
            turns=turns,
        )

        if verbose and reply.text:
            print(f"\n🤖 [step {step}] {reply.text}\n")

        # If the model did not ask for tools, it is done — capture the report.
        if not reply.wants_tools:
            run.report = reply.text
            run.stopped_reason = reply.stop_reason or "end_turn"
            return run

        # Record the assistant turn (must be echoed back verbatim next round).
        turns.append(Turn(role="assistant", text=reply.text, tool_calls=reply.tool_calls))

        # Execute every tool call; append one neutral tool turn per call.
        for tc in reply.tool_calls:
            run.tool_calls.append({"name": tc.name, "input": tc.input})
            if verbose:
                print(f"🔧 [step {step}] {tc.name}({json.dumps(tc.input)})")

            result_json = _dispatch_tool(tc.name, tc.input, allowed_scope)
            run.tool_results.append(
                {"name": tc.name, "input": tc.input, "output": result_json}
            )
            turns.append(Turn(
                role="tool", tool_call_id=tc.id, name=tc.name, text=result_json,
            ))

    # Ran out of steps before the model finished.
    run.stopped_reason = "max_steps"
    run.report = (
        f"(Agent hit the {max_steps}-step limit before finishing. "
        f"Ran {len(run.tool_calls)} tool calls.)"
    )
    return run


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Autonomous recon agent (AUTHORIZED targets only)."
    )
    parser.add_argument("target", help="Host/IP/domain to recon (must be in scope).")
    parser.add_argument(
        "--provider", default="anthropic", choices=PROVIDERS,
        help="LLM provider. Default: anthropic.",
    )
    parser.add_argument(
        "--scope", action="append", default=None,
        help="Allowed scope entry (IP/CIDR/host). Repeatable. "
             "Defaults to localhost + private ranges.",
    )
    parser.add_argument("--model", default=None, help="Model id (provider default if unset).")
    parser.add_argument("--max-steps", type=int, default=10, help="Tool-call round cap.")
    parser.add_argument("--report-dir", default=None, help="Write HTML+MD report to this dir.")
    parser.add_argument("--quiet", action="store_true", help="Hide step-by-step output.")
    args = parser.parse_args(argv)

    if not has_api_key(args.provider):
        keys = " or ".join(env_key_for(args.provider))
        print(f"ERROR: set {keys} in your environment for provider "
              f"'{args.provider}'.", file=sys.stderr)
        return 2

    run = run_agent(
        args.target,
        provider=args.provider,
        model=args.model,
        allowed_scope=args.scope,
        max_steps=args.max_steps,
        verbose=not args.quiet,
    )

    print("\n" + "=" * 70)
    print(f"Recon finished: {run.steps} steps, {len(run.tool_calls)} tool calls "
          f"via {run.provider}/{run.model} (stopped: {run.stopped_reason}).")
    print("=" * 70 + "\n")
    print(run.report)

    if args.report_dir:
        try:
            from report import write_reports
            paths = write_reports(run, args.report_dir)
            print(f"\nReports written:\n  " + "\n  ".join(paths))
        except Exception as exc:  # pragma: no cover - reporting must not crash run
            print(f"\n(Report generation failed: {exc})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
