package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"
)

type Provider struct {
	APIURL string `toml:"api_url"`
	APIKey string `toml:"api_key"`
	Model  string `toml:"model"`
	// ExtraBody is merged into the top level of the chat-completions request
	// body — the escape hatch for provider-specific parameters (e.g.
	// DeepSeek's `thinking`) without per-provider code.
	ExtraBody map[string]any `toml:"extra_body"`
}

type Config struct {
	Port           int                 `toml:"port"`
	ShfmtPath      string              `toml:"shfmt_path"`
	ShellcheckPath string              `toml:"shellcheck_path"`
	Provider       string              `toml:"provider"`
	Providers      map[string]Provider `toml:"providers"`
}

// Built-in providers carry api_url and model defaults only; an api_key must
// always come from the config file.
var builtinProviders = map[string]Provider{
	"groq": {
		APIURL: "https://api.groq.com/openai/v1/chat/completions",
		Model:  "openai/gpt-oss-120b",
	},
	"deepseek": {
		APIURL: "https://api.deepseek.com/chat/completions",
		Model:  "deepseek-v4-flash",
		// Thinking mode defaults to enabled and makes autofix take minutes;
		// Groq rejects this field, hence extra_body rather than ChatRequest.
		ExtraBody: map[string]any{"thinking": map[string]any{"type": "disabled"}},
	},
}

func defaultConfig() Config {
	return Config{
		Port:           8085,
		ShfmtPath:      "shfmt",
		ShellcheckPath: "shellcheck",
	}
}

func configPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("cannot determine home directory: %v", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "bash-script-tools", "config.toml")
}

var envVarRegex = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv replaces ${VAR} with the environment value; unset vars expand to "".
func expandEnv(s string) string {
	return envVarRegex.ReplaceAllStringFunc(s, func(m string) string {
		return os.Getenv(m[2 : len(m)-1])
	})
}

func loadConfig() Config {
	cfg := defaultConfig()
	path := configPath()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		log.Printf("no config file at %s, using defaults", path)
		return cfg
	}
	if err != nil {
		log.Fatalf("cannot read config %s: %v", path, err)
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("malformed config %s: %v", path, err)
	}

	cfg.ShfmtPath = expandEnv(cfg.ShfmtPath)
	cfg.ShellcheckPath = expandEnv(cfg.ShellcheckPath)
	cfg.Provider = expandEnv(cfg.Provider)
	for name, p := range cfg.Providers {
		p.APIURL = expandEnv(p.APIURL)
		p.APIKey = expandEnv(p.APIKey)
		p.Model = expandEnv(p.Model)
		cfg.Providers[name] = p
	}
	return cfg
}

// activeProvider merges the selected provider's config table over its
// built-in defaults. ok is false when no provider is selected. A selector
// naming a provider with neither a table nor built-in defaults is fatal.
func (c Config) activeProvider() (p Provider, ok bool) {
	if c.Provider == "" {
		return Provider{}, false
	}
	base, isBuiltin := builtinProviders[c.Provider]
	user, hasTable := c.Providers[c.Provider]
	if !isBuiltin && !hasTable {
		log.Fatalf("unknown provider %q: no [providers.%s] table and no built-in defaults", c.Provider, c.Provider)
	}
	if user.APIURL != "" {
		base.APIURL = user.APIURL
	}
	if user.APIKey != "" {
		base.APIKey = user.APIKey
	}
	if user.Model != "" {
		base.Model = user.Model
	}
	if len(user.ExtraBody) > 0 {
		base.ExtraBody = user.ExtraBody
	}
	return base, true
}

const configTemplate = `# bash-script-tools configuration
# port = 8085
# shfmt_path = "shfmt"
# shellcheck_path = "shellcheck"

provider = "groq"

[providers.groq]
api_key = "${GROQ_API_KEY}"
# api_url = "https://api.groq.com/openai/v1/chat/completions"
# model = "openai/gpt-oss-120b"

[providers.deepseek]
api_key = "${DEEPSEEK_API_KEY}"
# api_url = "https://api.deepseek.com/chat/completions"
# model = "deepseek-v4-flash"
# Extra fields merged into the request body. Thinking is disabled by default
# (it makes autofix take minutes); uncomment to re-enable it:
# [providers.deepseek.extra_body]
# thinking = { type = "enabled" }
`

func runInit() {
	path := configPath()
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(os.Stderr, "config already exists at %s\n", path)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("cannot create config directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(configTemplate), 0o644); err != nil {
		log.Fatalf("cannot write config: %v", err)
	}
	fmt.Printf("wrote %s\n", path)
}
