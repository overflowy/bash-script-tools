package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	cfg       Config
	active    Provider
	hasActive bool
)

//go:embed index.html
var indexHTML string

type ShellcheckResponse struct {
	HTML        string       `json:"html"`
	Annotations []Annotation `json:"annotations"`
}

type Annotation struct {
	Row    int    `json:"row"`
	Column int    `json:"column"`
	Text   string `json:"text"`
	Type   string `json:"type"`
}

type LineError struct {
	Code     string
	Severity string
	Message  string
	Column   int
}

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "init" {
			runInit()
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command %q (available: init)\n", os.Args[1])
		os.Exit(1)
	}

	cfg = loadConfig()
	active, hasActive = cfg.activeProvider()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/format", handleFormat)
	http.HandleFunc("/shellcheck", handleShellcheck)
	http.HandleFunc("/autofix", handleAutofix)
	http.HandleFunc("/autofix-ai", handleAutofixAI)

	log.Printf("Server starting on http://localhost:%d", cfg.Port)
	log.Printf("Using shfmt: %s", cfg.ShfmtPath)
	log.Printf("Using shellcheck: %s", cfg.ShellcheckPath)
	switch {
	case !hasActive:
		log.Printf("AI autofix disabled: no provider selected in config")
	case active.APIKey == "":
		log.Printf("warning: api key for provider %q resolved empty; AI autofix disabled", cfg.Provider)
	default:
		log.Printf("AI autofix enabled: provider %q, model %s", cfg.Provider, active.Model)
	}
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(indexHTML))
	tmpl.Execute(w, nil)
}

func handleFormat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.Write([]byte(code))
		return
	}

	cmd := exec.Command(cfg.ShfmtPath, "-")
	cmd.Stdin = bytes.NewBufferString(code)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Printf("shfmt error: %v", err)
		w.Write([]byte(code))
		return
	}

	w.Write(out.Bytes())
}

func handleShellcheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		respondJSON(w, ShellcheckResponse{
			HTML:        `<div class="text-sm text-zinc-500">No code to check</div>`,
			Annotations: []Annotation{},
		})
		return
	}

	// Create temporary file for shellcheck
	tmpFile := filepath.Join(os.TempDir(), "script.sh")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		respondJSON(w, ShellcheckResponse{
			HTML:        fmt.Sprintf(`<div class="text-sm text-red-600">Error: %v</div>`, err),
			Annotations: []Annotation{},
		})
		return
	}
	defer os.Remove(tmpFile)

	// Run shellcheck
	cmd := exec.Command(cfg.ShellcheckPath, "-f", "tty", tmpFile)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.Run()

	output := out.String()
	if output == "" {
		output = stderr.String()
	}

	respondJSON(w, ShellcheckResponse{
		HTML:        formatShellcheckHTML(output),
		Annotations: parseShellcheckOutput(output),
	})
}

func respondJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func parseShellcheckOutput(output string) []Annotation {
	annotations := []Annotation{}
	lineErrors := make(map[int][]LineError)

	lines := regexp.MustCompile(`\r?\n`).Split(output, -1)
	scCodeRegex := regexp.MustCompile(`(SC\d+)\s+\((error|warning|info|style)\):\s*(.+)`)
	lineRegex := regexp.MustCompile(`\bline\s+(\d+):`)
	columnRegex := regexp.MustCompile(`^(\s*)\^`)

	var currentLine int
	var currentColumn int
	for _, line := range lines {
		// Extract line number
		if lineMatch := lineRegex.FindStringSubmatch(line); len(lineMatch) >= 2 {
			if num, err := strconv.Atoi(lineMatch[1]); err == nil {
				currentLine = num
				currentColumn = 0
			}
		}

		// Extract column position from ^-- marker
		if colMatch := columnRegex.FindStringSubmatch(line); len(colMatch) > 1 {
			currentColumn = len(colMatch[1])
		}

		// Extract error code and message
		if scMatch := scCodeRegex.FindStringSubmatch(line); currentLine > 0 && len(scMatch) >= 4 {
			lineErrors[currentLine] = append(lineErrors[currentLine], LineError{
				Code:     scMatch[1],
				Severity: scMatch[2],
				Message:  scMatch[3],
				Column:   currentColumn,
			})
		}
	}

	// Create annotations grouped by line
	for lineNum, errors := range lineErrors {
		if len(errors) == 0 {
			continue
		}

		// Determine annotation type based on most severe error
		annotationType := "info"
		column := 0
		for _, err := range errors {
			if err.Severity == "error" {
				annotationType = "error"
				break
			} else if err.Severity == "warning" && annotationType != "error" {
				annotationType = "warning"
			}
		}

		// Use column from first error (they should all be the same for a given line)
		if len(errors) > 0 {
			column = errors[0].Column
		}

		// Build combined error message with one line per issue
		var messages []string
		for _, err := range errors {
			messages = append(messages, fmt.Sprintf("%s: %s", err.Code, err.Message))
		}

		annotations = append(annotations, Annotation{
			Row:    lineNum - 1, // Ace uses 0-based indexing
			Column: column,
			Text:   strings.Join(messages, "\n"),
			Type:   annotationType,
		})
	}

	return annotations
}

func handleAutofix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.Write([]byte(code))
		return
	}

	// Create temporary file for shellcheck
	tmpFile := filepath.Join(os.TempDir(), "script.sh")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		log.Printf("autofix error: %v", err)
		w.Write([]byte(code))
		return
	}
	defer os.Remove(tmpFile)

	// Run shellcheck with --format=diff to get fixes
	cmd := exec.Command(cfg.ShellcheckPath, "-f", "diff", tmpFile)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.Run()

	diff := out.String()
	if diff == "" {
		// No fixes available, return original code
		w.Write([]byte(code))
		return
	}

	// Apply the diff using patch
	patchCmd := exec.Command("patch", tmpFile)
	patchCmd.Stdin = bytes.NewBufferString(diff)
	var patchStderr bytes.Buffer
	patchCmd.Stderr = &patchStderr

	if err := patchCmd.Run(); err != nil {
		log.Printf("patch error: %v - %s", err, patchStderr.String())
		w.Write([]byte(code))
		return
	}

	// Read the fixed file
	fixed, err := os.ReadFile(tmpFile)
	if err != nil {
		log.Printf("read error: %v", err)
		w.Write([]byte(code))
		return
	}

	w.Write(fixed)
}

type ChatRequest struct {
	Model          string         `json:"model"`
	Temperature    float64        `json:"temperature"`
	Messages       []ChatMessage  `json:"messages"`
	ResponseFormat map[string]any `json:"response_format"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

type FixedCodeResponse struct {
	FixedCode string `json:"fixed_code"`
}

func handleAutofixAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !hasActive || active.APIKey == "" {
		log.Printf("no usable AI provider configured")
		http.Error(w, "AI autofix not configured", http.StatusInternalServerError)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		w.Write([]byte(code))
		return
	}

	// Create temporary file for shellcheck
	tmpFile := filepath.Join(os.TempDir(), "script.sh")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		log.Printf("autofix-ai error: %v", err)
		w.Write([]byte(code))
		return
	}
	defer os.Remove(tmpFile)

	// Run shellcheck to get issues
	cmd := exec.Command(cfg.ShellcheckPath, "-f", "tty", tmpFile)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	cmd.Run()

	shellcheckOutput := out.String()
	if shellcheckOutput == "" {
		shellcheckOutput = stderr.String()
	}

	if shellcheckOutput == "" {
		// No issues to fix
		w.Write([]byte(code))
		return
	}

	// Build prompt for AI
	prompt := fmt.Sprintf(`Fix all ShellCheck issues in the following bash script. Respond with a JSON object of the form {"fixed_code": "<the complete fixed script>"} and nothing else.

ShellCheck Issues:
%s

Original Script:
%s`, shellcheckOutput, code)

	// json_object is the response format both Groq and DeepSeek support;
	// see docs/adr/0001-json-object-response-format.md
	reqBody := ChatRequest{
		Model:       active.Model,
		Temperature: 0,
		Messages: []ChatMessage{
			{
				Role:    "system",
				Content: `You are a bash script fixing assistant. Respond with a JSON object of the form {"fixed_code": "<the complete fixed script>"} without any markdown formatting or explanations.`,
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		ResponseFormat: map[string]any{
			"type": "json_object",
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		w.Write([]byte(code))
		return
	}

	// Call the provider API
	req, err := http.NewRequest("POST", active.APIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Request creation error: %v", err)
		w.Write([]byte(code))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+active.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request error: %v", err)
		w.Write([]byte(code))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("API error: %d %s: %s", resp.StatusCode, resp.Status, string(body))
		w.Write([]byte(code))
		return
	}

	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		log.Printf("JSON decode error: %v", err)
		w.Write([]byte(code))
		return
	}

	if len(chatResp.Choices) == 0 {
		log.Printf("No choices in response")
		w.Write([]byte(code))
		return
	}

	var fixedResp FixedCodeResponse
	if err := json.Unmarshal([]byte(chatResp.Choices[0].Message.Content), &fixedResp); err != nil {
		log.Printf("Fixed code parse error: %v", err)
		w.Write([]byte(code))
		return
	}

	w.Write([]byte(fixedResp.FixedCode))
}

func formatShellcheckHTML(output string) string {
	if output == "" {
		return `<div class="text-sm text-green-600">✓ No issues found</div>`
	}

	// Remove the full file path from "In /path/to/file line X:" to just "Line X:"
	pathRegex := regexp.MustCompile(`In .+/script\.sh line (\d+):`)
	output = pathRegex.ReplaceAllString(output, `Line $1:`)

	// Remove "For more information:" section
	lines := regexp.MustCompile(`\r?\n`).Split(output, -1)
	var filteredLines []string
	skipMode := false

	for _, line := range lines {
		if regexp.MustCompile(`(?i)^For more information:`).MatchString(line) {
			skipMode = true
			continue
		}
		if skipMode && regexp.MustCompile(`^\s+https://`).MatchString(line) {
			continue
		}
		if skipMode && !regexp.MustCompile(`^\s+https://`).MatchString(line) && line != "" {
			skipMode = false
		}
		if !skipMode {
			filteredLines = append(filteredLines, line)
		}
	}

	formatted := strings.Join(filteredLines, "\n")

	// Make SC codes clickable
	scCodeRegex := regexp.MustCompile(`(SC\d+)`)
	formatted = scCodeRegex.ReplaceAllStringFunc(formatted, func(code string) string {
		return fmt.Sprintf(`<a href="https://www.shellcheck.net/wiki/%s" target="_blank" class="text-blue-400 hover:text-blue-300 underline">%s</a>`, code, code)
	})

	// Color-code severity levels
	formatted = regexp.MustCompile(`(?m)^(.+SC\d+.+\(error\):.+)$`).ReplaceAllString(formatted, `<span class="text-red-400">$1</span>`)
	formatted = regexp.MustCompile(`(?m)^(.+SC\d+.+\(warning\):.+)$`).ReplaceAllString(formatted, `<span class="text-yellow-400">$1</span>`)
	formatted = regexp.MustCompile(`(?m)^(.+SC\d+.+\(info\):.+)$`).ReplaceAllString(formatted, `<span class="text-blue-400">$1</span>`)
	formatted = regexp.MustCompile(`(?m)^(.+SC\d+.+\(style\):.+)$`).ReplaceAllString(formatted, `<span class="text-green-400">$1</span>`)

	// Color line numbers and make them clickable (now just "Line X:")
	formatted = regexp.MustCompile(`(?m)^Line (\d+):`).ReplaceAllString(formatted, `<a href="#" class="line-link text-cyan-400 hover:text-cyan-300 cursor-pointer underline" data-line="$1">Line $1:</a>`)

	return fmt.Sprintf(`<pre class="text-xs whitespace-pre-wrap font-mono">%s</pre>`, formatted)
}
