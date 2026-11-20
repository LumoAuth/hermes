#!/usr/bin/env python3
"""Stage 1 of the end-to-end run: start ``hermes lumoauth setup`` against a real LumoAuth.

Creates a fresh run directory with a fake HOME, a Hermes home whose config.yaml
enables ``lumoauth`` (the plugin is copied in as a directory plugin) and a Guard
home. Starts setup in the background with its output in ``setup.log``, waits
until the log shows the approval link, the user code and the key fingerprint,
prints them and exits. Setup keeps waiting for a person to approve in LumoAuth.

    python e2e/start_setup.py --python /path/to/hermes-venv/bin/python \\
        --hermes-src /path/to/hermes-agent --ca-file /path/to/caddy-root.crt --root /path/to/run
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from common import DEFAULT_URL, Run, add_common_arguments, default_root, fail, install_plugin


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_common_arguments(parser)
    parser.add_argument("--python", required=True, help="a Python that can import hermes-agent and its deps")
    parser.add_argument("--hermes-src", default="", help="hermes-agent checkout for PYTHONPATH")
    parser.add_argument("--ca-file", default="", help="CA certificate of the LumoAuth server (SSL_CERT_FILE)")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"LumoAuth dashboard address (default {DEFAULT_URL})")
    parser.add_argument("--name", default="E2E Hermes", help="agent name in LumoAuth")
    parser.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for the approval link")
    args = parser.parse_args()

    run = Run(root=default_root(args.root), python=args.python, hermes_src=args.hermes_src, ca_file=args.ca_file)
    root = Path(run.root)
    if root.exists():
        pid_file = root / "setup.pid"
        if pid_file.exists():
            subprocess.run(["pkill", "-INT", "-F", str(pid_file)], check=False)
        shutil.rmtree(root)
    for directory in (run.project, run.bundled, run.hermes_home):
        directory.mkdir(parents=True, exist_ok=True)
    (run.hermes_home / "config.yaml").write_text(
        "# lumoauth-hermes end-to-end run\n"
        "plugins:\n  enabled: [lumoauth]\n"
        "approvals:\n  mode: manual\n",
        encoding="utf-8")
    (run.project / "notes.md").write_text("E2E notes: hello from the project directory.\n", encoding="utf-8")
    ssh = run.home / ".ssh"
    ssh.mkdir(mode=0o700)
    (ssh / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY----- E2E-FAKE-KEY -----END-----\n",
                                encoding="utf-8")
    install_plugin(run)
    run.save()

    command = [run.python, "-u", "-m", "hermes_cli.main", "lumoauth", "setup", "--url", args.url,
               "--preset", "assistant", "--approvals", "auto", "--yes", "--name", args.name]
    log = open(run.setup_log, "w", encoding="utf-8")  # noqa: SIM115 - handed to the child process
    process = subprocess.Popen(command, cwd=run.project, env=run.env(), stdout=log, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, start_new_session=True)
    (root / "setup.pid").write_text(f"{process.pid}\n", encoding="utf-8")

    deadline = time.monotonic() + args.timeout
    text = ""
    while time.monotonic() < deadline:
        text = run.setup_log.read_text(encoding="utf-8", errors="replace")
        if "Check key" in text or process.poll() is not None:
            break
        time.sleep(0.5)
    link = re.search(r"1\. Open\s+(\S+)", text)
    code = re.search(r"2\. Check code\s+(\S+)", text)
    key = re.search(r"3\. Check key\s+(\S+)", text)
    if not (link and code and key):
        print(text[-3000:], file=sys.stderr)
        fail(f"setup did not show the approval details (exit code {process.poll()}); log: {run.setup_log}")
    print(f"Verification URL: {link.group(1)}")
    print(f"User code:        {code.group(1)}")
    print(f"Key fingerprint:  {key.group(1)}")
    print(f"Setup log:        {run.setup_log}")
    print(f"Setup pid:        {process.pid} (still waiting for approval)")
    print(f"Run directory:    {run.root}")
    print(f"HOME:             {run.home}")
    print(f"HERMES_HOME:      {run.hermes_home}")
    print(f"Guard home:       {run.guard_home}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
