#!/usr/bin/env python3
"""Stage 2 of the end-to-end run: real Hermes tool calls through the Guard, against a real LumoAuth.

Run it after stage 1 finished (the agent is approved and setup wrote config.json):

    python e2e/run_calls.py --root /path/to/run

It starts itself again with the run's Python and environment, loads the
plugin through Hermes's own plugin discovery, sends each call through
``model_tools.handle_function_call`` (agent-loop tools through the same
pre_tool_call dispatch that the agent loop uses), answers every approval
prompt with "deny", and prints a table. Then it flushes the receipts and
runs ``hermes lumoauth status --json`` and ``hermes lumoauth doctor --json``.

``--approvals host`` (the default) makes this run use Hermes's own prompt, so
that no push request reaches the owner's phone; config.json is restored at
the end.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from common import Run, add_common_arguments, default_root

CHILD = "LUMOAUTH_E2E_CHILD"


def parent(args: argparse.Namespace) -> int:
    run = Run.load(default_root(args.root))
    env = run.env()
    env.update({CHILD: "1", "HERMES_INTERACTIVE": "1"})
    command = [run.python, str(Path(__file__).resolve()), "--root", run.root, "--approvals", args.approvals,
               "--wait", str(args.wait)]
    return subprocess.run(command, env=env, cwd=run.project, check=False).returncode


# (label, tool, arguments, expected, how): how is "call" (handle_function_call) or "hook"
# (the agent loop's pre_tool_call dispatch, for tools that only the agent loop runs).
CALLS = [
    ("read a project file", "read_file", {"path": "notes.md"}, "allowed", "call"),
    ("write a project file", "write_file", {"path": "e2e-out.txt", "content": "written by the e2e run\n"},
     "allowed", "call"),
    ("open a web page (taints)", "web_extract", {"urls": ["https://example.com"]}, "allowed", "call"),
    ("memory after taint", "memory", {"action": "add", "target": "memory", "content": "e2e: remember this"},
     "approve (tainted) -> denied", "hook"),
    ("send a message after taint", "discord", {"action": "send", "channel_id": "1", "content": "hi"},
     "approve (not granted) -> denied", "call"),
    ("read ~/.ssh/id_rsa", "read_file", {"path": "~/.ssh/id_rsa"}, "blocked (secrets)", "call"),
    ("cat Hermes config", "terminal", {"command": "cat ~/.hermes/config.yaml"}, "blocked (hostConfig)", "call"),
    ("disable the plugin", "terminal", {"command": "hermes plugins disable lumoauth"}, "blocked (command)", "call"),
    ("ungranted command", "terminal", {"command": "echo e2e-ungranted"}, "approve (not granted) -> denied", "call"),
    ("MCP delete", "mcp__github__delete_repository", {"owner": "acme", "repo": "x"},
     "approve (not granted) -> denied", "call"),
]


def child(args: argparse.Namespace) -> int:
    run = Run.load(default_root(args.root))
    # The plugin's own copy in the Hermes home: the same module that Hermes loads.
    sys.path.insert(0, str(run.hermes_home / "plugins" / "lumoauth" / "src"))
    from lumoauth_hermes.config import GuardHome as Home

    home = Home(run.guard_home)
    original = json.loads(home.config_path.read_text(encoding="utf-8"))
    if args.approvals and original.get("approvals") != args.approvals:
        home.write_config({**original, "approvals": args.approvals})
    try:
        return _calls(run, home, args)
    finally:
        home.write_config(original)


def _calls(run: Run, home, args: argparse.Namespace) -> int:
    import model_tools
    from hermes_cli import plugins
    from hermes_cli.lifecycle import invoke_hook
    from hermes_cli.plugins import resolve_pre_tool_block
    from tools.terminal_tool import set_approval_callback

    plugins.discover_plugins()
    import lumoauth_hermes

    guard = lumoauth_hermes._guard
    if guard is None:
        print("The lumoauth plugin did not load.", file=sys.stderr)
        return 1
    prompts: list[tuple[str, str]] = []

    def deny(command, description, **_kw):
        prompts.append((str(command), str(description)))
        return "deny"

    set_approval_callback(deny)
    rows = []
    for index, (label, tool, call_args, expected, how) in enumerate(CALLS, 1):
        before = len(prompts)
        ids = {"task_id": "e2e-task", "session_id": "e2e-session", "tool_call_id": f"e2e-{index}",
               "turn_id": "e2e-turn", "api_request_id": "e2e-req"}
        if how == "hook":
            blocked = resolve_pre_tool_block(tool, call_args, conversation_id="e2e-conv", **ids)
            result = blocked or "(the agent loop would run it)"
            # The agent loop reports a blocked call to post_tool_call too.
            invoke_hook("post_tool_call", tool_name=tool, args=call_args, result=result, conversation_id="e2e-conv",
                        duration_ms=0, status="blocked" if blocked else "ok", error_type=None, error_message=None,
                        middleware_trace=[], **ids)
        else:
            result = model_tools.handle_function_call(tool, call_args, conversation_id="e2e-conv", **ids)
        asked = prompts[before:]
        if "Blocked by LumoAuth Guard" in result:
            message = json.loads(result).get("error", result) if result.startswith("{") else result
            actual = "blocked: " + message.replace("Blocked by LumoAuth Guard. ", "")[:90]
        elif asked:
            why = next((line for line in asked[0][1].splitlines() if line.startswith("Why:")), "")
            actual = f"approve ({why[5:]}) -> denied"
        elif "BLOCKED" in result:
            actual = "blocked by Hermes: " + result[:80]
        else:
            actual = "allowed"
        ok = _matches(expected, actual)
        rows.append((label, tool, expected, actual, "ok" if ok else "DIFFERENT"))
    set_approval_callback(None)

    widths = [max(len(str(r[i])) for r in rows + [("Call", "Tool", "Expected", "Actual", "")]) for i in range(5)]
    header = ("Call", "Tool", "Expected", "Actual", "")
    print("  ".join(h.ljust(w) for h, w in zip(header, widths)))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(row, widths)))
    print()
    print(f"e2e-out.txt written by write_file: {(run.project / 'e2e-out.txt').exists()}")

    guard.flush()
    print(f"Waiting {args.wait:g} s for receipts to flush...")
    time.sleep(args.wait)
    guard.flush()
    guard.write_status()
    print(f"Receipts sent: {guard.receipts.sent}, queued: {len(guard.receipts)}, refused by LumoAuth: "
          f"{guard.receipts.rejected}, pending: {guard.receipts.pending_count}")
    print()
    env = dict(os.environ)
    env.pop(CHILD, None)
    for sub in (["status", "--json"], ["doctor", "--json"]):
        proc = subprocess.run([sys.executable, "-m", "hermes_cli.main", "lumoauth", *sub], env=env,
                              capture_output=True, text=True, timeout=300, check=False)
        print(f"$ hermes lumoauth {' '.join(sub)}   (exit {proc.returncode})")
        print(proc.stdout[proc.stdout.find("{"):] if "{" in proc.stdout else proc.stdout + proc.stderr[-2000:])
    return 0 if all(r[4] == "ok" for r in rows) else 1


def _matches(expected: str, actual: str) -> bool:
    if expected == "allowed":
        return actual == "allowed"
    if expected.startswith("blocked"):
        return actual.startswith("blocked:")
    if expected.startswith("approve (tainted)"):
        return actual.startswith("approve (After the agent read untrusted content)")
    if expected.startswith("approve (not granted)"):
        return actual.startswith("approve (Not granted to this agent)")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_arguments(parser)
    parser.add_argument("--approvals", default="host", choices=["host", "auto", "lumoauth", "off", ""],
                        help="approvals for this run only (default host: no push to the owner's phone)")
    parser.add_argument("--wait", type=float, default=10.0, help="seconds to wait for receipts (default 10)")
    args = parser.parse_args()
    return child(args) if os.environ.get(CHILD) else parent(args)


if __name__ == "__main__":
    sys.exit(main())
