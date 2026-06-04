"""
agent.py
========
The LLM tool-calling agent loop for the AI Pentesting / Recon Assistant.

This is the "brain" from the roadmap (Month 2): give it an authorized target,
and it autonomously decides which recon tools to run, reasons over the output,
and writes a first-draft security report.

How it works
------------
1. We hand Claude a system prompt (it is a careful, scope-aware junior pentester)
   plus the JSON schemas for every tool in the registry.
2. Claude replies. If it wants data, it emits one or more `tool_use` blocks.
3. We execute each requested tool via the registry, feed the JSON result back as
   a `tool_result`, and loop.
4. When Claude stops asking for tools, its final text is the security report.

The whole point of the wrappers is realized here: Claude only ever picks an
*intent* (a tool name + a few well-described args); the wrappers turn that into a
correct, safe command line and structured output.

SAFETY: every wrapper still enforces the scope allow-list at the code level, so
even if the model asks to scan something out of scope, the call is refused.

Usage
-----
    export ANTHROPIC_API_KEY=sk-...
    python agent.py 127.0.0.1
    python agent.py 192.168.56.101 --scope 192.168.56.0/24 --max-steps 12
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# The registry of the 5 web/recon tools, plus the shared scope guard.
from tool_wrappers import TOOL_REGISTRY as _WEB_REGISTRY
from nmap_wrapper import (
    NMAP_TOOL_SCHEMA,
    DEFAULT_ALLOWED_SCOPE,
    ScopeError,
    run_nmap,
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
    report: str = ""
    steps: int = 0
    tool_calls: list[dict] = field(default_factory=list)  # {name, input}
    stopped_reason: str = ""


def run_agent(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    model: str = "claude-opus-4-8",
    max_steps: int = 10,
    verbose: bool = True,
) -> AgentRun:
    """Drive Claude through an autonomous recon of `target`.

    Parameters
    ----------
    target : str
        Host/IP/domain to recon. Must be inside `allowed_scope`.
    allowed_scope : list[str], optional
        Scope allow-list passed to every tool. Defaults to localhost + private.
    model : str
        Anthropic model id.
    max_steps : int
        Hard cap on tool-calling rounds, so the agent can't loop forever.
    verbose : bool
        Print reasoning + tool calls as they happen.
    """
    try:
        from anthropic import Anthropic
    except ImportError:
        raise SystemExit(
            "The 'anthropic' package is required. Install it:  pip install anthropic"
        )

    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    client = Anthropic()  # reads ANTHROPIC_API_KEY from the environment

    # Anthropic tool schemas == our *_TOOL_SCHEMA dicts, unchanged.
    tools = [schema for (_func, schema) in TOOL_REGISTRY.values()]

    messages: list[dict] = [{
        "role": "user",
        "content": (
            f"Target: {target}\n"
            f"Authorized scope: {allowed_scope}\n\n"
            "Perform autonomous recon and produce the security report."
        ),
    }]

    run = AgentRun(target=target)

    for step in range(1, max_steps + 1):
        run.steps = step
        resp = client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        # Surface any text the model produced this turn.
        for block in resp.content:
            if block.type == "text" and block.text.strip():
                if verbose:
                    print(f"\n🤖 [step {step}] {block.text.strip()}\n")

        # If the model did not ask for tools, it is done — capture the report.
        if resp.stop_reason != "tool_use":
            run.report = "".join(
                b.text for b in resp.content if b.type == "text"
            ).strip()
            run.stopped_reason = resp.stop_reason or "end_turn"
            return run

        # Record the assistant turn (must be echoed back verbatim next round).
        messages.append({"role": "assistant", "content": resp.content})

        # Execute every tool_use block and gather the results for one user turn.
        tool_results: list[dict] = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            run.tool_calls.append({"name": block.name, "input": block.input})
            if verbose:
                print(f"🔧 [step {step}] {block.name}({json.dumps(block.input)})")

            result_json = _dispatch_tool(block.name, block.input, allowed_scope)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": result_json,
            })

        messages.append({"role": "user", "content": tool_results})

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
        "--scope", action="append", default=None,
        help="Allowed scope entry (IP/CIDR/host). Repeatable. "
             "Defaults to localhost + private ranges.",
    )
    parser.add_argument("--model", default="claude-opus-4-8", help="Anthropic model id.")
    parser.add_argument("--max-steps", type=int, default=10, help="Tool-call round cap.")
    parser.add_argument("--quiet", action="store_true", help="Hide step-by-step output.")
    args = parser.parse_args(argv)

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: set ANTHROPIC_API_KEY in your environment.", file=sys.stderr)
        return 2

    run = run_agent(
        args.target,
        allowed_scope=args.scope,
        model=args.model,
        max_steps=args.max_steps,
        verbose=not args.quiet,
    )

    print("\n" + "=" * 70)
    print(f"Recon finished: {run.steps} steps, {len(run.tool_calls)} tool calls "
          f"(stopped: {run.stopped_reason}).")
    print("=" * 70 + "\n")
    print(run.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
