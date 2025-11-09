# Bash Script Tools

A web-based bash script formatter and linter with AI-powered autofix.

## Features

- **Format**: Format bash scripts using `shfmt`
- **Lint**: Check scripts with `shellcheck`
- **Autofix**: Apply shellcheck's automatic fixes
- **Autofix (AI)**: Fix shellcheck issues using AI (Groq)

## Requirements

- Go 1.16+
- `shfmt` - [github.com/mvdan/sh](https://github.com/mvdan/sh)
- `shellcheck` - [github.com/koalaman/shellcheck](https://github.com/koalaman/shellcheck)

## Usage

```bash
# Basic usage
./bash-script-tools

# With AI autofix (optional)
export GROQ_API_KEY="your-api-key"
./bash-script-tools

# Custom configuration
export PORT=8085
export GROQ_MODEL_ID="openai/gpt-oss-120b"
export SHFMT_PATH="/custom/path/to/shfmt"
export SHELLCHECK_PATH="/custom/path/to/shellcheck"
./bash-script-tools
```

Open http://localhost:8085 in your browser.

## License

MIT
