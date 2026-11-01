#!/usr/bin/env python3
"""Poll Relay chat/tasks as implementer; emit AGENT_LOOP_TICK_relay_coord with inbox JSON."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = Path("/tmp/nozo-agent-last-msg")
BOOT = ROOT / "data" / "bootstrap_credentials.json"
BASE = "http://127.0.0.1:8765"


def api(key: str, path: str) -> dict:
    req = urllib.request.Request(
        BASE + path,
        headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def main() -> int:
    boot = json.loads(BOOT.read_text(encoding="utf-8"))
    key = boot["agents"][0]["key"]
    self_id = boot["agents"][0]["principal_id"]
    project_id = boot["project"]["id"]
    last = STATE.read_text(encoding="utf-8").strip() if STATE.is_file() else ""

    items = (api(key, f"/api/v1/projects/{project_id}/messages?limit=50").get("items") or [])
    task_items = (api(key, f"/api/v1/projects/{project_id}/tasks?limit=50").get("items") or [])

    new: list[dict] = []
    if last:
        after = False
        for m in items:
            if m["id"] == last:
                after = True
                continue
            if after and m.get("sender_id") != self_id:
                new.append(m)
    # else: cold start — do not dump history; cursor advances below

    if items:
        STATE.write_text(items[-1]["id"], encoding="utf-8")

    open_tasks = [t for t in task_items if t.get("status") not in ("done", "cancelled", "canceled")]
    inbox = {
        "new_messages": [
            {"id": m["id"], "kind": m.get("kind"), "body": m.get("body"), "sender_id": m.get("sender_id")}
            for m in new
        ],
        "open_tasks": [
            {"id": t["id"], "status": t.get("status"), "title": t.get("title") or t.get("summary")}
            for t in open_tasks
        ],
        "message_count": len(items),
        "task_count": len(task_items),
    }
    # Stay quiet unless there is new chat from others (avoid spamming empty ticks).
    if not inbox["new_messages"]:
        print("AGENT_LOOP_IDLE_relay_coord " + json.dumps({"inbox": {"new_messages": [], "message_count": len(items)}}))
        return 0
    prompt = (
        "You are connected to Nozo Relay as test-implementer. "
        "Inspect inbox.new_messages / inbox.open_tasks. "
        "If the coordinator (or owner) gave actionable instructions, execute them in the workspace "
        "and POST a status note to the project chat with the implementer Bearer key."
    )
    print("AGENT_LOOP_TICK_relay_coord " + json.dumps({"prompt": prompt, "inbox": inbox}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(
            "AGENT_LOOP_TICK_relay_coord "
            + json.dumps(
                {
                    "prompt": f"Relay poll failed: {e}. Ensure `nozo_relay serve` is up on :8765.",
                    "inbox": {},
                },
                ensure_ascii=False,
            )
        )
        raise SystemExit(0)
