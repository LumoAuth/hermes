"""``hermes lumoauth ...`` and the standalone ``lumoauth-hermes ...`` command (SPEC §8, §9)."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import doctor, status
from ._version import __version__
from .config import ConfigError, GuardHome
from .setup_flow import REGIONS, SetupOptions, run_setup

DESCRIPTION = ("LumoAuth Guard checks every tool call that Hermes makes, outside the model: it allows it, "
               "asks a person, or blocks it. Policy lives in LumoAuth.")


def build_parser(parser: argparse.ArgumentParser | None = None) -> argparse.ArgumentParser:
    """Add the sub-commands to ``parser`` (Hermes passes its ``lumoauth`` sub-parser)."""
    parser = parser or argparse.ArgumentParser(prog="lumoauth-hermes", description=DESCRIPTION)
    sub = parser.add_subparsers(dest="lumoauth_command", metavar="{setup,status,doctor,lock,unlock,reset}")

    setup = sub.add_parser("setup", help="enroll this Hermes as a LumoAuth agent",
                           description="Enroll this Hermes as a LumoAuth agent. A person approves it in LumoAuth.")
    setup.add_argument("--url", dest="la_url", help="your LumoAuth dashboard address, "
                       "for example https://app.lumoauth.dev/orgs/acme/portal")
    setup.add_argument("--region", dest="la_region", choices=sorted(REGIONS), help="hosted region (us or eu)")
    setup.add_argument("--org", dest="la_org", help="organization, when the address does not name one")
    setup.add_argument("--preset", dest="la_preset", choices=["observer", "assistant", "builder"],
                       help="what the agent may do without asking (default: assistant)")
    setup.add_argument("--approvals", dest="la_approvals", choices=["auto", "lumoauth", "host", "off"],
                       help="where a person approves (default: auto)")
    setup.add_argument("--receipts", dest="la_receipts", action=argparse.BooleanOptionalAction, default=None,
                       help="send LumoAuth a receipt for each decision, for its audit log (default: no)")
    setup.add_argument("--report-usage", dest="la_report_usage", action=argparse.BooleanOptionalAction,
                       default=None, help="send LumoAuth the number of model tokens that the agent uses, "
                       "for its token budgets (default: no)")
    setup.add_argument("--name", dest="la_name", help="the agent's name in LumoAuth")
    setup.add_argument("--yes", "-y", dest="la_yes", action="store_true", help="ask nothing; use defaults")
    setup.add_argument("--no-hermes-config", dest="la_no_host_config", action="store_true",
                       help="do not change Hermes's config.yaml")
    setup.add_argument("--force", dest="la_force", action="store_true",
                       help="replace an existing setup on this machine")

    st = sub.add_parser("status", help="identity, mode, capabilities, connectivity, recent decisions")
    st.add_argument("--json", dest="la_json", action="store_true", help="print JSON")
    st.add_argument("--offline", dest="la_offline", action="store_true", help="do not contact LumoAuth")

    doc = sub.add_parser("doctor", help="check the Guard and Hermes's security settings")
    doc.add_argument("--json", dest="la_json", action="store_true", help="print JSON")
    doc.add_argument("--offline", dest="la_offline", action="store_true", help="do not contact LumoAuth")

    lock = sub.add_parser("lock", help="block every tool call until you unlock")
    lock.add_argument("--reason", dest="la_reason", default="", help="why (kept in the lock file)")
    sub.add_parser("unlock", help="remove the local lock")

    reset = sub.add_parser("reset", help="delete the local key and configuration")
    reset.add_argument("--yes", "-y", dest="la_yes", action="store_true", help="do not ask for confirmation")
    parser.set_defaults(func=handle)
    return parser


def _arg(args: Any, name: str, default: Any = None) -> Any:
    return getattr(args, name, default)


def handle(args: argparse.Namespace) -> int:
    command = _arg(args, "lumoauth_command")
    home = GuardHome()
    if command == "setup":
        return run_setup(SetupOptions(
            url=_arg(args, "la_url"), region=_arg(args, "la_region"), org=_arg(args, "la_org"),
            preset=_arg(args, "la_preset"), approvals=_arg(args, "la_approvals"), name=_arg(args, "la_name"),
            receipts=_arg(args, "la_receipts"), report_usage=_arg(args, "la_report_usage"),
            yes=bool(_arg(args, "la_yes")), host_config=not _arg(args, "la_no_host_config"),
            force=bool(_arg(args, "la_force")),
        ), home=home)
    if command == "status":
        data = status.gather(home, live=not _arg(args, "la_offline"))
        print(json.dumps(data, indent=2) if _arg(args, "la_json") else status.format_text(data))
        return 0 if data.get("setUp") else 1
    if command == "doctor":
        checks = doctor.run(home, offline=bool(_arg(args, "la_offline")))
        if _arg(args, "la_json"):
            print(json.dumps(doctor.as_json(checks), indent=2))
        else:
            print("LumoAuth Guard doctor (changes nothing)")
            print(doctor.format_text(checks))
        return 0
    if command == "lock":
        home.lock(_arg(args, "la_reason", ""))
        print("Locked. Hermes blocks every tool call until you run `hermes lumoauth unlock`.")
        return 0
    if command == "unlock":
        print("Unlocked." if home.unlock() else "The Guard was not locked.")
        return 0
    if command == "reset":
        return _reset(home, bool(_arg(args, "la_yes")))
    print(f"lumoauth-hermes {__version__}. {DESCRIPTION}")
    print("Commands: setup, status, doctor, lock, unlock, reset. Add --help to any of them.")
    return 0


def _reset(home: GuardHome, yes: bool) -> int:
    try:
        cfg = home.read_config()
    except ConfigError:
        cfg = None
    if not yes:
        if not sys.stdin.isatty():
            print("Reset deletes this machine's agent key and settings. Run it again with --yes.")
            return 1
        answer = input(f"Delete the agent key and settings in {home.path}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Nothing was deleted.")
            return 1
    removed = []
    for path in (home.config_path, home.key_path, home.queue_path, home.status_path):
        try:
            path.unlink()
            removed.append(path.name)
        except FileNotFoundError:
            pass
    print("Deleted: " + (", ".join(removed) if removed else "nothing (it was not set up)") + ".")
    print("Hermes now blocks every tool call until you run `hermes lumoauth setup` again.")
    if home.is_locked():
        print("The local lock stays on: run `hermes lumoauth unlock` to remove it.")
    if cfg is not None:
        print(f"The agent {cfg.agent_id} stays in LumoAuth until you delete it there: {cfg.agent_url}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(handle(args) or 0)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
