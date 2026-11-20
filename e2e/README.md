
## Stage 2: tool calls

After the agent is approved and setup has finished:

```sh
python e2e/run_calls.py --root /path/to/run
```

The script runs again with the run's Python and environment. It loads the plugin through Hermes's own
plugin discovery and sends ten calls through `model_tools.handle_function_call`: allowed reads and
writes, a web page that marks the session as tainted, protected files and commands, and calls that
need approval. The `memory` call goes through the agent loop's `pre_tool_call` dispatch, because
`handle_function_call` refuses agent-loop tools. Every approval prompt is answered with "deny". The
script prints a table of expected and actual results, flushes the receipts, and prints
`hermes lumoauth status --json` and `hermes lumoauth doctor --json`.

By default the run uses `--approvals host`, so that no push request reaches the owner's phone. The
script writes that value into `config.json` for the run and restores the file at the end.
