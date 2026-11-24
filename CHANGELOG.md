# Changelog

## Unreleased

Changes asked for in the second review for the Hermes plugin catalog.

- Reporting is opt-in. `receipts` and `reportUsage` default to `false`, and `hermes lumoauth setup` asks about
  each one. The default answer is no. In a script, `--receipts` and `--report-usage` say yes, and `--yes` alone
  says no. Approval requests still send the call's title and argument lines, because the person needs them to
  decide.
- Setup's self-test sends its test receipt only when receipts are on.
- `status` shows whether receipts and token counts are on. The README lists what the Guard sends to LumoAuth.
- After an upgrade, an existing setup keeps `"receipts": true`, which setup wrote into `config.json`. Token
  counts stop, because setup never wrote `reportUsage`. To keep sending them, set `"reportUsage": true`.
- Contract: SPEC §3.1 lists `receipts` and `reportUsage`, both `false` by default, and setup asks about them
  (§8.1).

## 0.1.2 — 2026-11-23

Changes asked for in the review for the Hermes plugin catalog.

- `doctor` no longer reads Hermes's `.env` file or looks for secret values in `config.yaml`, which Hermes
  forbids plugins to do. The gateway checks read the environment, which the `hermes` command loads from `.env`
  when it starts. `secrets.plaintext` now reports only who may read `.env`. Run outside Hermes,
  `lumoauth-hermes doctor` says that it cannot see the gateway settings in `.env`.
- To learn whether Hermes would approve a call without asking, the Guard first reads `HERMES_YOLO_MODE` and
  `approvals.mode` from Hermes's config, then Hermes's public `is_approval_bypass_active()`. Hermes's private
  approval helpers come last, for `hermes -z` and unattended contexts. They can only add a reason to block, and
  when they change, the Guard does without them. `approval_context._get_approval_mode` is no longer used.
- Contract: the `secrets.plaintext` row of SPEC §9 says what the check covers on Hermes.

## 0.1.1 — 2026-11-20

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
