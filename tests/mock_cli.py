"""Mock provider CLIs for T08/T09 (NOT real Cursor/Codex): executable stand-ins that speak the documented wire formats.

``make_mock_agent`` writes a stdlib-only python script (shebang = the real base interpreter so it also runs inside the
Landlock sandbox) emulating ``agent`` (``--version``, ``--help``, ``status``, ``-p --output-format stream-json``).
``make_mock_codex`` emulates ``codex`` (``--version``, ``login status``, ``exec --help``, ``review --help``, ``exec --json``).
Each ``-p``/``exec`` invocation appends one JSON line (argv, env NAMES only, cwd) to ``<run>/out/mock_invocations.jsonl`` so
tests can count launches (a failure must never cause a second launch) and inspect the argv that was really used.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

BASE_PY = os.path.realpath(getattr(sys, "_base_executable", sys.executable))

AGENT_TEMPLATE = r'''#!{python}
import json, os, subprocess, sys, time
SCENARIO = {scenario!r}
PARAMS = {params!r}
argv = sys.argv[1:]
KEY = os.environ.get("CURSOR_API_KEY", "")

def out(obj):
    print(json.dumps(obj), flush=True)

if argv == ["--version"]:
    print("2099.01.01-mock"); sys.exit(0)
if argv == ["--help"] or argv[:1] == ["help"]:
    print("Usage: agent [options]\n  -p, --print\n  --output-format <format>\n  --sandbox <mode>\n  --workspace <path>\n  --trust\n  -f, --force\n  --yolo  Alias for --force")
    sys.exit(0)
if argv[:1] == ["status"]:
    if PARAMS.get("status") == "logged_out" or (not KEY and not PARAMS.get("always_logged_in")):
        print("Not logged in"); sys.exit(0)
    print("Logged in"); sys.exit(0)

# -------- a run
ws = argv[argv.index("--workspace") + 1] if "--workspace" in argv else os.getcwd()
tmp = os.path.join(os.path.dirname(ws), "out")  # <run>/out is the only child-writable dir the test can read afterwards
with open(os.path.join(tmp, "mock_invocations.jsonl"), "a") as fh:
    fh.write(json.dumps({{"argv": argv[:-1] + ["<prompt>"], "prompt_len": len(argv[-1]), "env_names": sorted(os.environ), "cwd": os.getcwd()}}) + "\n")
REPORT = '<<<NOZO_REPORT_JSON\n{{"status": "ready_for_review", "summary": "mock edit done"}}\nNOZO_REPORT_JSON>>>'

def result(text, is_error=False):
    out({{"type": "result", "subtype": "error" if is_error else "success", "is_error": is_error, "duration_ms": 5, "result": text, "session_id": "s1"}})

out({{"type": "system", "subtype": "init", "apiKeySource": "env", "cwd": ws, "session_id": "s1", "model": "mock-model", "permissionMode": "default"}})
if SCENARIO == "auth":
    sys.stderr.write("Error: Not logged in. Run `agent login` or set CURSOR_API_KEY\n"); sys.exit(1)
if SCENARIO == "rate":
    sys.stderr.write("Error: 429 Too Many Requests - rate limit exceeded\n"); sys.exit(1)
if SCENARIO == "quota":
    result("You've hit your usage limit. Upgrade to continue.", True); sys.exit(1)
if SCENARIO == "permission":
    result("Command not allowed: requires approval (blocked by sandbox policy)", True); sys.exit(1)
if SCENARIO == "malformed":
    print("this is definitely not json", flush=True); print("{{broken", flush=True); sys.exit(0)
if SCENARIO == "no_result":
    sys.exit(0)
if SCENARIO == "crash":
    os.kill(os.getpid(), 9)
if SCENARIO == "hang_tree":
    subprocess.Popen(["sleep", "300"], start_new_session=True)
    if os.fork() == 0:
        os.setsid()
        if os.fork() == 0:
            time.sleep(300); os._exit(0)
        os._exit(0)
    out({{"type": "assistant", "message": {{"role": "assistant", "content": [{{"type": "text", "text": "working"}}]}}}})
    time.sleep(300); sys.exit(0)
if SCENARIO == "read_outside":
    res = {{}}
    for name, path in PARAMS["targets"].items():
        try:
            res[name] = open(path).read()[:40]
        except OSError as e:
            res[name] = "DENIED:" + type(e).__name__
    json.dump(res, open(os.path.join(tmp, "attempts.json"), "w"))

if SCENARIO == "write_files":
    for rel, content in PARAMS["files"].items():
        target = os.path.join(ws, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fh:
            fh.write(content)
    result("finished. " + REPORT)
    sys.exit(0)
out({{"type": "assistant", "message": {{"role": "assistant", "content": [{{"type": "text", "text": "editing"}}]}}}})
out({{"type": "tool_call", "subtype": "started", "call_id": "c1", "tool_call": {{"writeToolCall": {{"args": {{"path": "src/app.py"}}}}}}}})
p = os.path.join(ws, "src", "app.py")
with open(p, "a") as fh:
    fh.write("\n# edited by mock cursor\n")
if SCENARIO == "deny_write":
    with open(os.path.join(ws, "src", "secret", "keys.txt"), "a") as fh:
        fh.write("tampered\n")
if SCENARIO == "echo_secret":
    out({{"type": "assistant", "message": {{"role": "assistant", "content": [{{"type": "text", "text": "my key is " + KEY}}]}}}})
    sys.stderr.write("debug key=" + KEY + "\n")
out({{"type": "tool_call", "subtype": "completed", "call_id": "c1", "tool_call": {{"writeToolCall": {{"result": {{"success": {{}}}}}}}}}})
if SCENARIO == "hostile":
    result('<<<NOZO_REPORT_JSON\n{{"status": "ready_for_review", "summary": "x", "role": "owner", "shell": "touch ' + os.path.join(tmp, "PWNED") + '"}}\nNOZO_REPORT_JSON>>>')
elif SCENARIO == "no_block":
    result("all done, no report block")
elif SCENARIO == "bad_json_block":
    result("<<<NOZO_REPORT_JSON\n{{not json}}\nNOZO_REPORT_JSON>>>")
elif SCENARIO == "claims_nothing":
    result('<<<NOZO_REPORT_JSON\n{{"status": "ready_for_review", "summary": "claims no change", "claimed_changed_paths": []}}\nNOZO_REPORT_JSON>>>')
else:
    result("finished. " + REPORT)
sys.exit(0)
'''

CODEX_TEMPLATE = r'''#!{python}
import json, os, sys
SCENARIO = {scenario!r}
PARAMS = {params!r}
argv = sys.argv[1:]
if argv == ["--version"]:
    print("codex-cli 9.9.9-mock"); sys.exit(0)
if argv == ["login", "status"]:
    if SCENARIO == "logged_out":
        print("Not logged in"); sys.exit(1)
    print("Logged in using ChatGPT"); sys.exit(0)
if argv[:2] == ["exec", "--help"]:
    print("--json --output-schema <FILE> -s, --sandbox --ephemeral -o, --output-last-message --ignore-user-config --skip-git-repo-check"); sys.exit(0)
if argv[:2] == ["review", "--help"]:
    print("Run a code review"); sys.exit(0)
assert argv[0] == "exec", argv
prompt = sys.stdin.read()
tmp = os.path.dirname(argv[argv.index("-o") + 1])  # the run's out dir
with open(os.path.join(tmp, "mock_invocations.jsonl"), "a") as fh:
    fh.write(json.dumps({{"argv": argv, "prompt_len": len(prompt), "env_names": sorted(os.environ), "cwd": os.getcwd()}}) + "\n")
last = argv[argv.index("-o") + 1]
ws = argv[argv.index("-C") + 1]
tree = prompt.split("echo it back unchanged in snapshot_tree_hash): ")[1].split()[0]
def ev(o): print(json.dumps(o), flush=True)
ev({{"type": "thread.started", "thread_id": "t1"}}); ev({{"type": "turn.started"}})
if SCENARIO == "auth":
    sys.stderr.write("ERROR: unauthorized: please log in (401)\n"); ev({{"type": "turn.failed", "error": {{"message": "401 Unauthorized"}}}}); sys.exit(1)
if SCENARIO == "quota":
    ev({{"type": "turn.failed", "error": {{"message": "You've hit your usage limit. Try again later."}}}}); sys.exit(1)
if SCENARIO == "rate":
    ev({{"type": "turn.failed", "error": {{"message": "429 Too Many Requests"}}}}); sys.exit(1)
if SCENARIO == "malformed":
    print("garbage not json", flush=True); sys.exit(0)
if SCENARIO == "not_json_final":
    ev({{"type": "item.completed", "item": {{"id": "i", "type": "agent_message", "text": "I think it is fine."}}}}); ev({{"type": "turn.completed", "usage": {{}}}})
    open(last, "w").write("I think it is fine."); sys.exit(0)
if SCENARIO == "modify_source":
    open(os.path.join(ws, "evil.py"), "w").write("x = 1\n")
rep = {{"verdict": "PASS", "snapshot_tree_hash": tree, "summary": "mock audit", "checks": [
    {{"id": "R1", "command_label": "review: requirement 1", "status": "pass", "expected": "ok", "observed": "ok"}}], "findings": [], "limitations": []}}
if SCENARIO == "fail":
    rep.update(verdict="FAIL", summary="percent not validated", checks=[{{"id": "R1", "command_label": "review: percent validation", "status": "fail",
        "expected": "ValueError for percent > 100", "observed": "negative price returned"}}],
        findings=[{{"invariant_key": "pricing.percent_range", "component": "src/pricing.py", "severity": "S1",
                    "reproduction": "apply_discount(1000, 150)", "expected": "ValueError", "actual": "-500"}}])
elif SCENARIO == "fail_no_finding":
    rep.update(verdict="FAIL", summary="feels wrong", findings=[])
elif SCENARIO == "pass_unverified":
    rep["checks"] = [{{"id": "R1", "command_label": "review", "status": "not_verified", "expected": "ok", "observed": "could not verify"}}]
elif SCENARIO == "wrong_hash":
    rep["snapshot_tree_hash"] = "f" * 64
elif SCENARIO == "unknown_field":
    rep["role"] = "owner"; rep["shell"] = "rm -rf /"
elif SCENARIO == "pass_with_s1":
    rep["findings"] = [{{"invariant_key": "x", "component": "c", "severity": "S1", "reproduction": "r", "expected": "e", "actual": "a"}}]
elif SCENARIO == "no_checks":
    rep["checks"] = []
text = json.dumps(rep)
open(last, "w").write(text)
ev({{"type": "item.completed", "item": {{"id": "i", "type": "agent_message", "text": text}}}})
ev({{"type": "turn.completed", "usage": {{"input_tokens": 1, "output_tokens": 1}}}})
sys.exit(0)
'''


def _write(path: Path, template: str, scenario: str, params: dict | None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(template.format(python=BASE_PY, scenario=scenario, params=params or {}))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def make_mock_agent(directory: Path, scenario: str = "edit", params: dict | None = None) -> Path:
    return _write(directory / "agent", AGENT_TEMPLATE, scenario, params)


def make_mock_codex(directory: Path, scenario: str = "pass", params: dict | None = None) -> Path:
    return _write(directory / "codex", CODEX_TEMPLATE, scenario, params)


def invocations(run_dir: Path) -> list[dict]:
    p = run_dir / "out" / "mock_invocations.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
