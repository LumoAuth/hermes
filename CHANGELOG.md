# Changelog

## Unreleased

- `plugin.yaml` declares `requires_hermes: ">=0.21.6"`, the oldest Hermes Agent release that the plugin is tested with. Hermes skips the plugin on an older release instead of loading it.
- CI runs the tests inside a real Hermes Agent every week, on `main` and on 0.21.6, and runs `hermes plugins validate`.
- The README documents the `reportUsage` setting.

## 0.1.0 — 2026-11-20

First release of LumoAuth Guard for Hermes Agent (`lumoauth-hermes`, plugin `lumoauth`).

- Checks every tool call in Hermes's `pre_tool_call` hook: allows it, asks a person, or blocks it.
- Classification, hard rules, decision order, taint and approval text from the LumoAuth Guard contract v1.
- Approvals in Hermes's own prompt (terminal panel or chat buttons) or in the LumoAuth app.
- Blocks instead of approving when Hermes would approve without asking (`approvals.mode: off`, `--yolo`,
  unattended `approve` modes).
- Agent identity with `private_key_jwt` and DPoP; the private key stays in `~/.lumoauth/guard/hermes/`.
- Audit entries for every decision, with a SHA-256 digest of the arguments; model token usage reports.
- Commands: `hermes lumoauth setup | status | doctor | lock | unlock | reset`, `/lumoauth`, and the
  standalone `lumoauth-hermes`.
- The `lumoauth-guard` skill.
- Contract v1 as of 2026-11-19: `hostSkills` path class, home-relative roots in the shell scan, path checks
  for MCP and plugin tool arguments, snapshot check before every approval, "session"/"always" answers only
  for capabilities that are not granted, disguising characters shown as U+FFFD in approval text.
- LumoAuth approvals reach the owner's app and the organization's Slack and Discord approval channels: the
  request carries `expires_in` and a structured `meta`, and `status` shows where it waits.
- §4.1a dispatcher tools (catalog `dispatcher` field) with single-use 60 s pre-decisions.
