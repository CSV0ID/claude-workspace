"""
Pytest suite for the AI Pentesting / Recon Assistant.

These tests run WITHOUT any external scanner binaries or network access:
  * Parsers are tested against captured sample output.
  * The scope guard is tested directly.
  * The agent loop is driven by a FakeProvider (no real API calls).

Run:  cd nmap/tools && python3 -m pytest -q
"""

from __future__ import annotations

import os
import sys

import pytest

# Make the tools package importable when running from the repo root or here.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nmap_wrapper as nm  # noqa: E402
import tool_wrappers as tw  # noqa: E402
import report as rp  # noqa: E402
import llm  # noqa: E402
import agent  # noqa: E402


# ===========================================================================
# Scope guard
# ===========================================================================

class TestScope:
    def test_localhost_in_scope(self):
        assert nm.is_in_scope("127.0.0.1", nm.DEFAULT_ALLOWED_SCOPE)
        assert nm.is_in_scope("localhost", nm.DEFAULT_ALLOWED_SCOPE)

    def test_private_cidr_in_scope(self):
        assert nm.is_in_scope("192.168.1.50", nm.DEFAULT_ALLOWED_SCOPE)
        assert nm.is_in_scope("10.1.2.3", nm.DEFAULT_ALLOWED_SCOPE)

    def test_public_ip_out_of_scope(self):
        assert not nm.is_in_scope("8.8.8.8", nm.DEFAULT_ALLOWED_SCOPE)

    def test_unknown_hostname_out_of_scope(self):
        assert not nm.is_in_scope("evil.example.com", nm.DEFAULT_ALLOWED_SCOPE)

    def test_custom_scope_exact_host(self):
        assert nm.is_in_scope("scanme.nmap.org", ["scanme.nmap.org"])

    def test_run_nmap_raises_scopeerror(self):
        with pytest.raises(nm.ScopeError):
            nm.run_nmap("8.8.8.8", scan_type="quick")


# ===========================================================================
# nmap profiles / command building / validation
# ===========================================================================

class TestNmapProfiles:
    def test_all_profiles_present(self):
        for key in ["ping", "quick", "full", "vuln", "web", "stealth", "os"]:
            assert key in nm.SCAN_PROFILES

    def test_schema_enum_matches_profiles(self):
        enum = nm.NMAP_TOOL_SCHEMA["input_schema"]["properties"]["scan_type"]["enum"]
        assert set(enum) == set(nm.SCAN_PROFILES)

    def test_unknown_scan_type_errors(self):
        # In scope, but bad scan_type -> structured error, no exception.
        res = nm.run_nmap("127.0.0.1", scan_type="nope")
        assert not res.success
        assert "Unknown scan_type" in res.error

    def test_bad_port_spec_errors(self):
        res = nm.run_nmap("127.0.0.1", scan_type="quick", ports="80; rm -rf /")
        assert not res.success
        assert "Invalid port spec" in res.error

    def test_disallowed_script_category(self):
        res = nm.run_nmap("127.0.0.1", scan_type="quick", scripts="exploit")
        assert not res.success
        assert "Disallowed script categories" in res.error

    def test_bad_script_args(self):
        res = nm.run_nmap("127.0.0.1", scan_type="quick", script_args="a=$(reboot)")
        assert not res.success
        assert "Invalid script_args" in res.error

    def test_bad_timing(self):
        res = nm.run_nmap("127.0.0.1", scan_type="quick", timing=9)
        assert not res.success
        assert "Invalid timing" in res.error


# ===========================================================================
# nmap XML parser
# ===========================================================================

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="lab.local" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.4" accuracy="96"/></os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0">
          <cpe>cpe:/a:nginx:nginx</cpe>
        </service>
        <script id="http-title" output="Welcome to nginx"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb-os-discovery" output="OS: Windows"/>
    </hostscript>
  </host>
</nmaprun>"""


class TestNmapParser:
    def test_parse_basic_fields(self):
        hosts = nm._parse_nmap_xml(SAMPLE_NMAP_XML)
        assert len(hosts) == 1
        h = hosts[0]
        assert h["address"] == "192.168.1.10"
        assert h["state"] == "up"
        assert h["hostnames"] == ["lab.local"]
        assert h["os"] == {"name": "Linux 5.4", "accuracy": 96}

    def test_parse_ports_and_scripts(self):
        h = nm._parse_nmap_xml(SAMPLE_NMAP_XML)[0]
        assert len(h["ports"]) == 2
        http = [p for p in h["ports"] if p["port"] == 80][0]
        assert http["service"] == "http"
        assert http["product"] == "nginx"
        assert http["scripts"]["http-title"] == "Welcome to nginx"
        assert "cpe:/a:nginx:nginx" in http["cpe"]

    def test_parse_hostscripts(self):
        h = nm._parse_nmap_xml(SAMPLE_NMAP_XML)[0]
        assert h["hostscripts"]["smb-os-discovery"] == "OS: Windows"

    def test_parse_empty_and_garbage(self):
        assert nm._parse_nmap_xml("") == []
        assert nm._parse_nmap_xml("not xml <<<") == []

    def test_result_summary(self):
        res = nm.NmapResult(
            target="192.168.1.10", command=["nmap"], success=True,
            hosts=nm._parse_nmap_xml(SAMPLE_NMAP_XML),
        )
        s = res.summary()
        assert "192.168.1.10" in s
        assert "OpenSSH" in s
        assert "Linux 5.4" in s


# ===========================================================================
# tool_wrappers — parsers + registry + scope
# ===========================================================================

class TestToolWrappers:
    def test_registry_size(self):
        assert len(tw.TOOL_REGISTRY) == 12
        for name, (func, schema) in tw.TOOL_REGISTRY.items():
            assert callable(func)
            assert schema["name"] == name

    def test_jsonl_parser(self):
        text = '{"a":1}\n\n{"b":2}\nnot json\n'
        assert tw._parse_jsonl(text) == [{"a": 1}, {"b": 2}]

    def test_nikto_parser(self):
        out = '[{"vulnerabilities":[{"id":"X","method":"GET","url":"/","msg":"m"}]}]'
        parsed = tw._parse_nikto(out)
        assert parsed == [{"id": "X", "method": "GET", "url": "/", "msg": "m"}]

    def test_ffuf_parser(self):
        out = '{"results":[{"url":"http://h/a","status":200,"length":5,"words":2}]}'
        parsed = tw._parse_ffuf(out)
        assert parsed[0]["status"] == 200

    def test_host_only(self):
        assert tw._host_only("http://192.168.1.5:8080/path") == "192.168.1.5"
        assert tw._host_only("https://lab.local") == "lab.local"

    def test_scope_guard_blocks(self):
        with pytest.raises(nm.ScopeError):
            tw.run_subfinder("evil.com", allowed_scope=["lab.local"])

    def test_missing_binary_returns_error(self):
        # None of these binaries are installed in the test env -> graceful error.
        res = tw.run_nuclei("127.0.0.1")
        assert not res.success
        assert "not installed" in res.error

    def test_nuclei_bad_severity(self):
        # Needs to pass the install check first; skip if nuclei somehow exists.
        import shutil
        if shutil.which("nuclei"):
            pytest.skip("nuclei installed; install-guard path not exercised")
        res = tw.run_nuclei("127.0.0.1", severity="urgent")
        assert not res.success


# ===========================================================================
# llm provider layer (translation only — no network)
# ===========================================================================

class TestLLMLayer:
    def test_providers_and_defaults(self):
        assert set(llm.PROVIDERS) == {"anthropic", "openai", "openrouter", "gemini"}
        for p in llm.PROVIDERS:
            assert p in llm.DEFAULT_MODELS

    def test_openai_tool_translation(self):
        schema = [{"name": "run_nmap", "description": "d",
                   "input_schema": {"type": "object", "properties": {}}}]
        out = llm.OpenAICompatProvider._tools(schema)
        assert out[0]["type"] == "function"
        assert out[0]["function"]["name"] == "run_nmap"
        assert out[0]["function"]["parameters"] == schema[0]["input_schema"]

    def test_anthropic_message_translation(self):
        turns = [
            llm.Turn("user", text="hi"),
            llm.Turn("assistant", text="ok",
                     tool_calls=[llm.ToolCall("id1", "run_nmap", {"target": "x"})]),
            llm.Turn("tool", tool_call_id="id1", name="run_nmap", text="{}"),
        ]
        msgs = llm.AnthropicProvider._messages(turns)
        assert msgs[0]["role"] == "user"
        assert msgs[1]["content"][1]["type"] == "tool_use"
        assert msgs[2]["content"][0]["type"] == "tool_result"

    def test_openai_message_translation(self):
        turns = [
            llm.Turn("user", text="hi"),
            llm.Turn("assistant", tool_calls=[llm.ToolCall("id1", "run_nmap", {"t": 1})]),
            llm.Turn("tool", tool_call_id="id1", name="run_nmap", text="{}"),
        ]
        msgs = llm.OpenAICompatProvider._messages("sys", turns)
        assert msgs[0]["role"] == "system"
        assert msgs[2]["tool_calls"][0]["function"]["name"] == "run_nmap"
        assert msgs[3]["role"] == "tool"

    def test_env_key_lookup(self):
        assert llm.env_key_for("anthropic") == ["ANTHROPIC_API_KEY"]
        assert "GEMINI_API_KEY" in llm.env_key_for("gemini")

    def test_unknown_provider(self):
        with pytest.raises(ValueError):
            llm.make_provider("nosuch")


# ===========================================================================
# agent loop driven by a fake provider (no API calls)
# ===========================================================================

class FakeProvider(llm.LLMProvider):
    """Scripted provider: yields a queue of LLMReply objects in order."""
    name = "fake"
    model = "fake-1"

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls = 0

    def chat(self, *, system, tools, turns, max_tokens=4096):
        self.calls += 1
        return self._replies.pop(0)


class TestAgentLoop:
    def test_full_agent_registry(self):
        # nmap + 12 web tools.
        assert len(agent.TOOL_REGISTRY) == 13
        assert "run_nmap" in agent.TOOL_REGISTRY

    def test_dispatch_unknown_tool(self):
        out = agent._dispatch_tool("run_nope", {}, nm.DEFAULT_ALLOWED_SCOPE)
        assert "Unknown tool" in out

    def test_dispatch_scope_error(self):
        out = agent._dispatch_tool(
            "run_nmap", {"target": "8.8.8.8", "scan_type": "quick"},
            nm.DEFAULT_ALLOWED_SCOPE,
        )
        assert "ScopeError" in out

    def test_dispatch_bad_args(self):
        out = agent._dispatch_tool("run_nmap", {"bogus": 1}, nm.DEFAULT_ALLOWED_SCOPE)
        assert "Bad arguments" in out

    def test_agent_runs_tool_then_reports(self):
        # Round 1: model asks for a tool. Round 2: model writes the report.
        replies = [
            llm.LLMReply(
                text="Scanning.",
                tool_calls=[llm.ToolCall("c1", "run_nmap",
                                         {"target": "127.0.0.1", "scan_type": "ping"})],
                stop_reason="tool_use",
            ),
            llm.LLMReply(text="# Security Report: 127.0.0.1\nAll clear.",
                         stop_reason="end_turn"),
        ]
        fake = FakeProvider(replies)
        run = agent.run_agent("127.0.0.1", provider=fake, verbose=False)
        assert run.steps == 2
        assert len(run.tool_calls) == 1
        assert run.tool_calls[0]["name"] == "run_nmap"
        assert "Security Report" in run.report
        assert run.stopped_reason == "end_turn"
        # A tool result was captured for the report appendix.
        assert len(run.tool_results) == 1

    def test_agent_respects_max_steps(self):
        # Model always asks for a tool -> loop must stop at max_steps.
        looping = llm.LLMReply(
            text="again",
            tool_calls=[llm.ToolCall("c", "run_nmap",
                                     {"target": "127.0.0.1", "scan_type": "ping"})],
            stop_reason="tool_use",
        )
        fake = FakeProvider([looping] * 10)
        run = agent.run_agent("127.0.0.1", provider=fake, max_steps=3, verbose=False)
        assert run.steps == 3
        assert run.stopped_reason == "max_steps"


# ===========================================================================
# report generator
# ===========================================================================

def _make_run():
    run = agent.AgentRun(
        target="192.168.1.10", provider="anthropic", model="claude-opus-4-8",
        steps=2, stopped_reason="end_turn",
    )
    run.report = (
        "# Security Report: 192.168.1.10\n"
        "## Findings\n- Severity: high\n- Severity: medium\n- Severity: high\n"
    )
    run.tool_calls = [{"name": "run_nmap", "input": {"target": "192.168.1.10"}}]
    run.tool_results = [
        {"name": "run_nmap", "input": {"target": "192.168.1.10"},
         "output": '{"hosts": []}'},
    ]
    return run


class TestReport:
    def test_count_severities(self):
        counts = rp.count_severities("Severity: high\nseverity:  Medium\nSeverity: high")
        assert counts["high"] == 2
        assert counts["medium"] == 1

    def test_render_markdown(self):
        md = rp.render_markdown(_make_run())
        assert "Security Report" in md
        assert "Appendix" in md
        assert "run_nmap" in md

    def test_render_html_escapes(self):
        run = _make_run()
        run.report = "# R\n<script>alert(1)</script>"
        h = rp.render_html(run)
        # Autoescape must neutralise the injected tag.
        assert "<script>alert(1)</script>" not in h
        assert "&lt;script&gt;" in h

    def test_render_html_badges(self):
        h = rp.render_html(_make_run())
        assert "High: 2" in h
        assert "Medium: 1" in h

    def test_write_reports(self, tmp_path):
        paths = rp.write_reports(_make_run(), str(tmp_path))
        assert len(paths) == 2
        for p in paths:
            assert os.path.exists(p)
        assert paths[0].endswith(".md")
        assert paths[1].endswith(".html")

    def test_safe_name(self):
        assert rp._safe_name("http://h/x?y") == "http___h_x_y"


# ===========================================================================
# Offline recon (no LLM): run tools, save bundle to disk, build LLM prompt
# ===========================================================================

import offline_recon as off  # noqa: E402


class TestOfflineRecon:
    def test_out_of_scope_refused_runs_nothing(self):
        b = off.run_offline_recon("8.8.8.8", verbose=False)
        assert b.stopped_reason == "scope_refused"
        assert b.steps == 0
        assert b.tool_results == []

    def test_in_scope_runs_plan(self):
        # nmap binary may be absent; tools then return failed results, but the
        # planner must still execute and record them without crashing.
        b = off.run_offline_recon("127.0.0.1", do_web=False, verbose=False)
        assert b.stopped_reason == "offline_recon"
        assert b.steps >= 1
        names = [c["name"] for c in b.tool_calls]
        assert "run_nmap" in names

    def test_open_web_targets_detection(self):
        res = nm.NmapResult(
            target="10.0.0.5", command=[], success=True,
            hosts=[{"address": "10.0.0.5", "state": "up", "ports": [
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https"},
                {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-alt"},
                {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
            ]}],
        )
        urls = off._open_web_targets(res, "10.0.0.5")
        assert "https://10.0.0.5" in urls
        assert "http://10.0.0.5:8080" in urls
        assert all("22" not in u for u in urls)  # ssh ignored

    def test_bundle_to_payload_shape(self):
        b = off.run_offline_recon("127.0.0.1", do_web=False, verbose=False)
        payload = off.bundle_to_payload(b)
        assert payload["schema"] == "recon-bundle/v1"
        assert payload["target"] == "127.0.0.1"
        assert "results" in payload and "plan" in payload

    def test_save_bundle_writes_json(self, tmp_path):
        b = off.run_offline_recon("127.0.0.1", do_web=False, verbose=False)
        paths = off.save_bundle(b, str(tmp_path), write_report=False)
        assert os.path.exists(paths["json"])
        assert paths["json"].endswith(".json")

    def test_payload_to_prompt_includes_target_and_format(self):
        b = off.run_offline_recon("127.0.0.1", do_web=False, verbose=False)
        prompt = off.payload_to_prompt(off.bundle_to_payload(b))
        assert "127.0.0.1" in prompt
        assert "Security Report" in prompt
        assert "Severity" in prompt
