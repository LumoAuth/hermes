<div align="center">

# LumoAuth Guard for Hermes Agent

**Check every tool call that your Hermes agent makes, before the tool runs.**<br>
Each call is allowed, sent to a person for approval, or blocked, by rules that you keep in LumoAuth.

[![PyPI](https://img.shields.io/pypi/v/lumoauth-hermes?style=flat-square&label=PyPI&color=111111)](https://pypi.org/project/lumoauth-hermes/)
[![CI](https://img.shields.io/github/actions/workflow/status/lumoauth/hermes/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/lumoauth/hermes/actions/workflows/ci.yml)
![Python 3.11 or later](https://img.shields.io/badge/python-3.11%2B-111111?style=flat-square)
[![License: MIT](https://img.shields.io/badge/license-MIT-111111?style=flat-square)](LICENSE)

[Quick start](#quick-start) · [What it protects](#what-it-protects) · [Approvals](#approvals) · [Everyday commands](#everyday-commands) · [Troubleshooting](#troubleshooting) · [Documentation](https://docs.lumoauth.dev/agents/personal-agents)

</div>

---

Your Hermes agent reads files, runs commands, browses the web and sends messages for you.
To do that, it reads text that other people wrote: web pages, e-mails, documents and chat messages.
Any of that text can contain instructions that you never gave.

**LumoAuth Guard** is a Hermes plugin that checks each tool call before the tool runs.
The check happens in Hermes's own process, outside the model. The Guard does not trust the model, so nothing in the conversation can change what the Guard decides.
You keep the rules in LumoAuth: the list of capabilities that you grant to the agent.

```text
      Your agent wants to run a tool
                     │
                     ▼
   ┌──────────────────────────────────┐       ┌──────────────────────────┐
   │  LumoAuth Guard                  │ ◀──── │  LumoAuth                │
   │  inside Hermes, outside          │       │  · what the agent may do │
   │  the model                       │ ────▶ │  · approvals             │
   └──────────────────────────────────┘       │  · audit log             │
          │          │          │             └──────────────────────────┘
          ▼          ▼          ▼
       ✓ runs   ? asks you  ✗ blocked
```

## Why use it

- **Rules that you control.** You grant the agent capabilities such as `files:write`, `shell:exec` or `mcp:github:read:*`. The Guard reloads them from LumoAuth every minute.
- **Approvals where you are.** A call that needs approval goes to the LumoAuth app on your phone, to Slack or Discord, or to Hermes's own approval prompt.
- **Protected, whatever you grant.** The agent can never read the Guard's key, change Hermes's settings, turn plugins off or open your credential stores.
- **Extra care after untrusted content.** After the agent reads a web page, an e-mail or a chat message, calls that send data out need approval.
- **No silent approvals.** When Hermes would approve without asking (`--yolo`, or approvals switched off), the Guard blocks the call instead.
- **A record of every decision, if you want one.** When you turn on receipts in setup, each decision becomes an entry in LumoAuth's audit log. Argument values stay on your machine.
- **Fails closed.** Every tool call is blocked until setup finishes. Calls are also blocked when LumoAuth cannot confirm the agent's permissions for longer than 5 minutes.

## Quick start

You need:

- Hermes Agent 0.21.6 or later, running on Python 3.11 or later.
- A LumoAuth organization. [Create one](https://app.lumoauth.dev/register) if you don't have one yet.

### 1. Install the plugin

```sh
hermes plugins install lumoauth/hermes --enable --yes-deps
```

Hermes scans every plugin before it installs it.
The scan reports that this plugin names credential paths such as `~/.ssh`, and asks you to confirm.
The Guard names those paths to protect them. Answer `y`.

From now until setup finishes, Hermes blocks every tool call. That is on purpose: the Guard fails closed.

### 2. Run setup

```sh
hermes lumoauth setup
```

Setup asks for the address of your LumoAuth dashboard, for example `https://app.lumoauth.dev/orgs/acme/portal`.
It asks what the agent may do without asking (a [preset](#presets)) and where a person should approve calls.
It also asks whether to send LumoAuth a receipt for each decision, and the number of model tokens that the agent uses.
Both answers default to no. See [What it sends to LumoAuth](#what-it-sends-to-lumoauth).
Then it creates a key for the agent and prints a link:

```text
Approve this agent in LumoAuth:

  1. Open        https://app.lumoauth.dev/orgs/acme/portal/agents/enroll?code=KQPM-WTRD
  2. Check code  KQPM-WTRD
  3. Check key   Hc4T-9wQe-Lm2P-x7Ra
  4. Review what the agent may do, then approve.

Approve only if you ran this command yourself just now and the code and key match.
Waiting for approval (Ctrl-C to stop)...
```

### 3. Approve the agent in LumoAuth

Open the link and sign in. Check that the page shows the same code and key as your terminal.
The page lists the capabilities that the preset ticked. Change the ticks if you like, then approve.

> **Approve only an agent that you set up yourself, just now.**
> If someone sends you a code or a link, deny it. Approving it would give their machine access to your organization in your name.

Setup then continues on its own. It saves its settings, runs a self-test and lists what the agent may do without asking:

```text
Approved. Agent agt_3f9c1d2e8a7b6054 is set up; settings are in /home/you/.lumoauth/guard/hermes/config.json.
Receipts: off. Token counts: off. To change them, set `receipts` or `reportUsage` in config.json.
Hermes: plugins.hook_callback_timeout: 180.
Self-test: token ............ ok
Self-test: capabilities ..... ok (agent active)
Self-test: receipt .......... skipped (receipts are off)

Granted capabilities (14): files:read, files:write, media:generate, media:read, memory:write, sessions:read, shell:read, skills:read, tasks:write, tools:read, ui:write, user:ask, web:fetch, web:search
Everything else asks a person first or is blocked.
```

### 4. Restart Hermes

Restart Hermes, or the Hermes gateway, so that it loads the Guard.

### Try it

Ask your agent to run `hermes plugins disable lumoauth`. The Guard blocks the call, and the model gets the reason:

```text
Blocked by LumoAuth Guard. Protected by a rule that cannot be changed: runs the Hermes admin command `hermes plugins`.
```

Then run `hermes lumoauth status`. It shows the agent, its capabilities, the connection to LumoAuth and the latest decisions.

<details>
<summary><b>Set up without questions, for scripts</b></summary>

<br>

```sh
hermes plugins install lumoauth/hermes --enable --yes-deps --force
hermes lumoauth setup --url https://app.lumoauth.dev/orgs/acme/portal --preset assistant --approvals auto --yes
```

A script cannot answer the scan question, so it needs `--force`.
With `--yes`, setup sends no receipts and no token counts. Add `--receipts` or `--report-usage` to send them.
You still approve the agent in LumoAuth: setup prints the link and waits for you.

</details>

<details>
<summary><b>Other ways to install</b></summary>

<br>

- **With pip**, in the Python environment that runs Hermes: `pip install lumoauth-hermes`, then `lumoauth-hermes setup`. Setup turns the plugin on in Hermes's `config.yaml`.
- **As a plain directory:** copy this repository to `~/.hermes/plugins/lumoauth`, run `hermes plugins enable lumoauth`, then `hermes lumoauth setup`.

</details>

## What it protects

| Area | What the Guard does |
|---|---|
| **Tool calls** | It checks every call that goes through Hermes's tool hook: built-in tools, MCP tools (`mcp__<server>__<tool>`), plugin tools, the tools of `delegate_task` sub-agents and the tool calls that `execute_code` scripts make. For MCP and plugin tools, argument values that start with `/` or `~/` are checked as paths. |
| **Its own files** | No setting, capability or approval lets the agent read the Guard's key, change Hermes's or the Guard's settings, turn plugins off, update Hermes or run `hermes plugins`, `hermes config` or `hermes lumoauth`. The agent may read Hermes's skills, but writing them as files is blocked. |
| **Secrets on disk** | Reading or writing `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, browser profiles, Hermes's `.env`, `auth.json` and `mcp-tokens` is blocked. A `.env` or `*.pem` file elsewhere needs a person's approval. |
| **Untrusted content** | After the agent reads a web page, search results, e-mail or chat messages, calls that send data out need approval, even when they are granted. Writing to memory or skills needs approval too. |
| **Identity** | The agent signs in with its own key pair (`private_key_jwt`). Its tokens work only with a short-lived key that this Hermes process holds (DPoP). The private key never leaves the machine, and there is no shared secret. |
| **Kill switch** | When you suspend or delete the agent in LumoAuth, every tool call stops within one minute. `hermes lumoauth lock` stops them at once on this machine. |
| **Audit trail** | When receipts are on, every decision becomes an entry in LumoAuth's audit log. The entry holds a SHA-256 digest of the arguments, never the arguments. |
| **Hermes settings** | `hermes lumoauth doctor` checks Hermes's own security settings and says what to change. |

## How a call is decided

The Guard checks these steps in order. The first step that matches gives the result.

1. **Locked?** When the local lock is on, the call is blocked.
2. **Not set up?** The call is blocked.
3. **Protected?** The protected files and commands above are blocked, or always need a person's approval.
4. **No confirmation from LumoAuth?** The Guard needs a recent list of the agent's capabilities. It refreshes the list every 60 seconds. When LumoAuth cannot be reached, the last list stays valid for 5 more minutes. After that, or when the agent is suspended, the call is blocked.
5. **Granted?** The call runs. After untrusted content, a call that sends data out needs approval.
6. **Not granted?** A person is asked. With `onUngranted: block`, the call is blocked.

Each tool call maps to one capability:

| Kind of tool | Capability | Example |
|---|---|---|
| Built-in tools | A fixed capability for each tool | `files:read`, `shell:exec`, `messages:send` |
| MCP tools | `mcp:<server>:<risk>:<tool>` | `mcp:github:read:list_issues`. Grant `mcp:github:read:*` for all read tools of the GitHub server. |
| Plugin tools | `tool:<name>` | `tool:weather` |

When the Guard blocks a call, the model gets a short message with the reason.
When a capability is missing, the message names it and links to the agent in LumoAuth, so that the owner can add it.

## Presets

Setup asks for a preset. The preset ticks capabilities on the approval page in LumoAuth.
You can change the ticks there before you approve, and later in LumoAuth.

| Preset | Runs without asking |
|---|---|
| `observer` | Reading files, searching and opening web pages, reading sessions and media, the read tools of MCP servers. |
| `assistant` (default) | Everything in `observer`, plus writing files and memory, to-do lists, generating media and the write tools of MCP servers. |
| `builder` | Everything in `assistant`, plus shell commands, code, background processes, sub-agents and the browser. |

No preset grants sending messages, scheduled jobs, device control, stored secrets, Hermes administration or skill changes.
You can grant them in LumoAuth on purpose.

## Approvals

The `approvals` setting chooses where a person approves:

| Value | Where |
|---|---|
| `auto` (default) | A LumoAuth approval when the agent may act for its owner. Otherwise, or when LumoAuth cannot reach anyone, Hermes's own prompt. |
| `lumoauth` | Only a LumoAuth approval. |
| `host` | Only Hermes's own prompt: the panel in the terminal, or the `/approve` and `/deny` buttons in a chat. |
| `off` | Nowhere: every call that needs approval is blocked. |

### On your phone, in Slack or in Discord

A LumoAuth approval goes to the owner only.
LumoAuth sends it to the owner's LumoAuth app on their phone, and to your organization's Slack and Discord approval channels.
The first answer counts.

A call stays on hold until the person answers.
`hermes lumoauth status` and `/lumoauth` show where a person can answer, for example "Waiting for approval in Slack".

LumoAuth approvals need the agent's **Can act on behalf of users** switch in LumoAuth.
This switch and the approval channels are part of the Agent Governance add-on.
Set up the channels in LumoAuth under **Integrations → Approval channels**.

<details>
<summary><b>How long a call can stay on hold</b></summary>

<br>

Hermes stops waiting for a plugin after `plugins.hook_callback_timeout` seconds (30 by default).
Setup sets it to 180 when LumoAuth approvals are possible.
The Guard stops waiting 5 seconds before Hermes does, and LumoAuth keeps the request open for that long (at least 60 seconds, at most 600).

</details>

### In Hermes

Approvals in Hermes work on every LumoAuth plan.
Hermes's prompt offers "once", "session" and "always".

- The Guard honours "session" and "always" for a capability that is not granted, unless `rememberApprovals` is `false`.
- For protected files and commands, and after untrusted content, every call asks again.
- Hermes approves without asking when `approvals.mode` is `off`, under `--yolo` or `/yolo`, and in a cron job whose `approvals.cron_mode` is `approve`. In those cases the Guard blocks the call instead, so that no call skips the person.

### What a request shows

Every request shows the tool, the reason, the capability, the risk and up to five arguments.
Values of arguments named like passwords, tokens, keys or cookies are hidden.

## What it sends to LumoAuth

The Guard talks only to the LumoAuth organization that you named in setup.
There is no other telemetry.

| What | When |
|---|---|
| A token request, signed with the agent's key | When the agent's token runs out. |
| A request for the agent's capabilities | Every minute. |
| An approval request: the tool, the reason, the capability, the risk and up to five argument lines | When a call waits for a LumoAuth approval. The person needs these to decide. Secret values are hidden. |
| A receipt: the tool, the decision, how the call ended and a SHA-256 digest of the arguments, never their values | For each decision, only if you said yes in setup (`receipts`). |
| The number of model tokens that the agent used | Once a minute, only if you said yes in setup (`reportUsage`). LumoAuth needs it for the token budgets that you set for the agent. |
| The capability that a call needs | For each call, only with `decisionMode: server`, which you set yourself. LumoAuth's Ask API decides and records the answer. |

## Everyday commands

| What you want | Command |
|---|---|
| See the agent, its capabilities, the connection and recent decisions | `hermes lumoauth status` |
| Check the Guard and Hermes's security settings | `hermes lumoauth doctor` |
| Stop every tool call on this machine, at once | `hermes lumoauth lock` |
| Let tool calls run again | `hermes lumoauth unlock` |
| Replace the setup on this machine with a new agent | `hermes lumoauth setup --force` |
| Delete the key and the settings on this machine | `hermes lumoauth reset` |

In a chat, `/lumoauth` shows a short status and `/lumoauth lock` locks the Guard.
Unlocking is only possible in a terminal.

`lumoauth-hermes` runs the same commands when the plugin is not loaded, for example `lumoauth-hermes doctor`.
Unlike `hermes`, it does not load Hermes's `.env`, so its doctor cannot check the gateway settings kept there.

<details>
<summary><b>All options</b></summary>

<br>

| Command | Options |
|---|---|
| `setup` | `--url <dashboard address>` · `--region us\|eu` · `--org <organization>` · `--preset observer\|assistant\|builder` · `--approvals auto\|lumoauth\|host\|off` · `--receipts` / `--no-receipts` · `--report-usage` / `--no-report-usage` (both default to no) · `--name <agent name>` · `--yes` asks nothing · `--force` replaces an existing setup · `--no-hermes-config` leaves Hermes's `config.yaml` unchanged |
| `status` | `--json` prints JSON · `--offline` skips LumoAuth |
| `doctor` | `--json` prints JSON · `--offline` skips LumoAuth. It changes nothing. It never opens Hermes's `.env` and never looks for secret values in `config.yaml`: for those files, it checks only who may read them. |
| `lock` | `--reason <text>` keeps a note in the lock file. |
| `reset` | `--yes` skips the question. The agent stays in LumoAuth until you delete it there; the command prints the link. |

</details>

The agent also gets the `lumoauth-guard` skill.
The skill tells the model what the Guard is and how to behave when a call is blocked or waits for approval.

## Configuration

The Guard keeps its files in `~/.lumoauth/guard/hermes/`, or in the directory named by `LUMOAUTH_GUARD_HOME`.
The directory has mode `0700` and the files have mode `0600`. The agent can neither read nor change them.

<details>
<summary><b>Files</b></summary>

<br>

| File | Content |
|---|---|
| `config.json` | Settings. Setup writes it. |
| `agent-key.pem` | The agent's private key (EC P-256). |
| `lock` | Present while the lock is on. |
| `receipts-queue.jsonl` | Audit entries that could not be sent before Hermes stopped. |
| `runtime-status.json` | Counters and recent decisions of the running Hermes, for `status`. |

</details>

<details>
<summary><b>Settings in <code>config.json</code></b></summary>

<br>

| Key | Values | Default | Meaning |
|---|---|---|---|
| `decisionMode` | `local`, `server` | `local` | `local` checks capabilities on this machine. `server` asks LumoAuth's Ask API for each call and records each answer there. |
| `approvals` | `auto`, `lumoauth`, `host`, `off` | `auto` | Where a person approves. |
| `onUngranted` | `ask`, `block` | `ask` | Whether a call without a granted capability asks a person or is blocked. |
| `taint.enabled` | `true`, `false` | `true` | Whether untrusted content raises the bar for later calls. |
| `taint.windowSeconds` | 60 to 86400 | 1800 | How long a session stays marked after untrusted content. |
| `taint.escalate` | risks, plus `egress` | `["external"]` | What needs approval after untrusted content. Strict: `["external", "execute", "egress"]`. |
| `refreshSeconds` | 30 to 600 | 60 | How often the capability list is refreshed. |
| `offlineGraceSeconds` | 0 to 3600 | 300 | How long the last list stays valid when LumoAuth cannot be reached. |
| `receipts` | `true`, `false` | `false` | Whether a receipt for each decision is sent to LumoAuth's audit log. Setup asks. |
| `reportUsage` | `true`, `false` | `false` | Whether the number of model tokens that the agent uses is sent to LumoAuth, once a minute. LumoAuth counts them against the token budgets that you can set for the agent. Setup asks. |
| `rememberApprovals` | `true`, `false` | `true` | Whether "session" and "always" answers in Hermes's prompt count for a capability that is not granted. |
| `extraProtectedPaths` | paths | `[]` | More paths to treat like credential stores. |
| `allowPaths` | paths | `[]` | Paths inside the Hermes home that the agent may use, for example a folder of notes. It never opens Hermes's settings, credentials or the Guard's files. |

You can edit these keys; the Guard reads the file again on the next call.
A value that is out of range falls back to its default. `status` and `doctor` show it.

</details>

## Limits

The Guard is strong, but it is not a sandbox. Please read these limits.

- **The Guard runs inside Hermes.** An agent that can run any code as your user (`terminal`, `execute_code`) could change files that the Guard does not see it touch. The Guard scans shell commands and code for protected paths and commands, but a scan only finds known patterns: it is not a sandbox. Use the Guard with Hermes's Docker backend (`hermes config set terminal.backend docker`). `doctor` checks this.
- **Calls that bypass Hermes's tool hook are not seen.** These are subprocesses that an `execute_code` script starts itself, `!cmd` shell escapes typed in the terminal, and tools that another plugin runs directly with `ctx.dispatch_tool`.
- **Safe mode turns the Guard off.** `hermes --safe-mode` and `HERMES_SAFE_MODE=1` start Hermes without any plugin. The Guard blocks the agent from starting Hermes that way, but a person can.
- **Other plugins are trusted code.** They run in the same process. A plugin that rewrites a call's arguments (a `modify` answer to `pre_tool_call`) changes them after the Guard has checked them.
- **New Hermes tools.** A tool that is not in this plugin's catalog counts as an unknown tool (`tool:<name>`, risk `execute`): it asks a person until you grant it.
- **Plugins in a separate process.** With `plugins.isolation: host`, Hermes runs plugins in their own process. There the Guard may not see a `/yolo` that someone turned on in a chat. Use `approvals: lumoauth` or `off` with that setting.
- **Hermes's program files.** The Guard protects the Hermes home (`~/.hermes`). When Hermes is installed somewhere else, protect that place with file permissions or a container.

## Troubleshooting

| What you see | What to do |
|---|---|
| "LumoAuth Guard is not set up" on every call | Run `hermes lumoauth setup`. |
| "LumoAuth cannot confirm this agent's permissions" | Run `hermes lumoauth status`. It shows whether LumoAuth can be reached and whether the agent is active. |
| "The agent is not active in LumoAuth" | The agent is suspended or deleted. Reactivate it in LumoAuth, or run setup again. |
| A tool always asks for approval | Its capability is not granted. The message names it; add it to the agent in LumoAuth. |
| LumoAuth approvals never arrive | Run `hermes lumoauth doctor`. The agent needs permission to act for its owner, and the owner needs the LumoAuth app or an approval channel in Slack or Discord. |
| A call stops after about 30 seconds | Hermes stopped waiting for the plugin. Run `hermes config set plugins.hook_callback_timeout 180`. |
| An MCP capability does not match | Hermes writes a server called `my-server` as `my_server` in tool names, so grant `mcp:my_server:...`. |
| "approvals are switched off in Hermes" | Hermes would approve without asking. Run `hermes config set approvals.mode manual` and start Hermes without `--yolo`. |
| A TLS error, when LumoAuth uses a private certificate authority | The TLS check uses your system's trusted certificates. Set `SSL_CERT_FILE` to the certificate of that authority. |

## Uninstall

```sh
hermes lumoauth reset --yes
hermes plugins remove lumoauth
```

Then delete the agent in LumoAuth: `reset` prints its link.
Removing the plugin without `reset` leaves the key in `~/.lumoauth/guard/hermes/`.

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python scripts/sync_contract.py --check
.venv/bin/ruff check .
.venv/bin/python -m pytest
```

The contract (SPEC, catalog, test vectors and skill) comes from the [`agent-guard`](https://github.com/lumoauth/agent-guard) repository.
`scripts/sync_contract.py` copies it into the package; the test vectors go to `tests/contract/vectors`.
A test fails when the copy differs.
`tests/test_real_hermes.py` loads the plugin into a real Hermes Agent, and skips when Hermes is not installed.
To run it, install the plugin into the environment of a Hermes Agent checkout, as CI does every week:

```sh
git clone --depth 1 https://github.com/NousResearch/hermes-agent.git ../hermes-agent
(cd ../hermes-agent && uv sync --frozen --no-dev)
uv pip install --python ../hermes-agent/.venv/bin/python -e ".[dev]"
../hermes-agent/.venv/bin/python -m pytest
../hermes-agent/.venv/bin/hermes plugins validate . --install-deps
```

The last command is the check that the Hermes plugin catalog runs.

## See also

- [LumoAuth Guard for OpenClaw](https://github.com/lumoauth/openclaw): the same protection for OpenClaw.
- [Secure OpenClaw and Hermes agents](https://docs.lumoauth.dev/agents/personal-agents): the guide in the LumoAuth documentation.
- [LumoAuth Guard contract](https://github.com/lumoauth/agent-guard): the open specification and the test cases that this plugin passes.

## License

MIT. See [LICENSE](LICENSE).
