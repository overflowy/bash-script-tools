# Bash Script Tools

A web-based bash script formatter and linter with AI-powered autofix.

https://github.com/user-attachments/assets/fd71cf96-f690-439c-9ebb-8f3844137dfc

## Features

- **Format**: Format bash scripts using `shfmt`
- **Lint**: Check scripts with `shellcheck`
- **Autofix**: Apply shellcheck's automatic fixes
- **Autofix (AI)**: Fix shellcheck issues using an AI provider (Groq, DeepSeek, or any OpenAI-compatible endpoint)

## Requirements

- Go 1.21+
- `shfmt` - [github.com/mvdan/sh](https://github.com/mvdan/sh)
- `shellcheck` - [github.com/koalaman/shellcheck](https://github.com/koalaman/shellcheck)

## Usage

```bash
./bash-script-tools
```

Open http://localhost:8085 in your browser. Formatting and linting work with
zero configuration; AI autofix needs a config file (below).

## Configuration

All configuration lives in `$XDG_CONFIG_HOME/bash-script-tools/config.toml`
(`~/.config/bash-script-tools/config.toml` when `XDG_CONFIG_HOME` is unset).
Generate a starter config with:

```bash
./bash-script-tools init
```

Every key is optional and falls back to its default. `${VAR}` in any string
value is replaced with that environment variable (empty if unset) - use it to
keep API keys out of the file:

```toml
# port = 8085
# shfmt_path = "shfmt"
# shellcheck_path = "shellcheck"

# Which provider handles AI autofix. Omit to disable AI autofix.
provider = "deepseek"

[providers.groq]
api_key = "${GROQ_API_KEY}"
# api_url = "https://api.groq.com/openai/v1/chat/completions"
# model = "openai/gpt-oss-120b"

[providers.deepseek]
api_key = "${DEEPSEEK_API_KEY}"
# api_url = "https://api.deepseek.com/chat/completions"
# model = "deepseek-v4-flash"
```

A provider table can also set `extra_body` — fields merged into the
chat-completions request body, for provider-specific parameters. The built-in
deepseek defaults use it to disable thinking mode (which would make autofix
take minutes); re-enable it with:

```toml
[providers.deepseek.extra_body]
thinking = { type = "enabled" }
```

`groq` and `deepseek` have built-in defaults for `api_url` and `model`, so
their tables only need an `api_key`. Any other OpenAI-compatible endpoint
works too - add a table with all three keys:

```toml
provider = "ollama"

[providers.ollama]
api_url = "http://localhost:11434/v1/chat/completions"
api_key = "unused"
model = "qwen2.5-coder"
```

If the selected provider's key resolves empty, the server still starts - AI
autofix is just disabled. A malformed config file or a `provider` naming
something unknown is a startup error.

## License

MIT
