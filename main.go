package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
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
	shfmtPath      = getEnvOrDefault("SHFMT_PATH", "shfmt")
	shellcheckPath = getEnvOrDefault("SHELLCHECK_PATH", "shellcheck")
	groqAPIKey     = os.Getenv("GROQ_API_KEY")
	groqModelID    = getEnvOrDefault("GROQ_MODEL_ID", "openai/gpt-oss-120b")
	groqAPIURL     = getEnvOrDefault("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
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

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/format", handleFormat)
	http.HandleFunc("/shellcheck", handleShellcheck)
	http.HandleFunc("/autofix", handleAutofix)
	http.HandleFunc("/autofix-ai", handleAutofixAI)

	port := getEnvOrDefault("PORT", "8085")
	log.Printf("Server starting on http://localhost:%s", port)
	log.Printf("Using shfmt: %s", shfmtPath)
	log.Printf("Using shellcheck: %s", shellcheckPath)
	if groqAPIKey != "" {
		log.Printf("AI autofix enabled with model: %s", groqModelID)
	}
	log.Fatal(http.ListenAndServe(":"+port, nil))
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

	cmd := exec.Command(shfmtPath, "-")
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
	cmd := exec.Command(shellcheckPath, "-f", "tty", tmpFile)
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

func respondJSON(w http.ResponseWriter, data interface{}) {
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
	cmd := exec.Command(shellcheckPath, "-f", "diff", tmpFile)
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

type GroqRequest struct {
	Model          string                 `json:"model"`
	Temperature    float64                `json:"temperature"`
	Messages       []GroqMessage          `json:"messages"`
	ResponseFormat map[string]interface{} `json:"response_format"`
}

type GroqMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type GroqResponse struct {
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

	if groqAPIKey == "" {
		log.Printf("GROQ_API_KEY not set")
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
	cmd := exec.Command(shellcheckPath, "-f", "tty", tmpFile)
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
	prompt := fmt.Sprintf(`Fix all ShellCheck issues in the following bash script. Return ONLY the fixed code without any explanations, markdown formatting, or code blocks.

ShellCheck Issues:
%s

Original Script:
%s`, shellcheckOutput, code)

	// Prepare Groq API request
	reqBody := GroqRequest{
		Model:       groqModelID,
		Temperature: 0,
		Messages: []GroqMessage{
			{
				Role:    "system",
				Content: "You are a bash script fixing assistant. Return only the fixed code without any markdown formatting or explanations.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		ResponseFormat: map[string]interface{}{
			"type": "json_schema",
			"json_schema": map[string]interface{}{
				"name": "fixed_script",
				"schema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"fixed_code": map[string]interface{}{
							"type": "string",
						},
					},
					"required": []string{"fixed_code"},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		w.Write([]byte(code))
		return
	}

	// Call Groq API
	req, err := http.NewRequest("POST", groqAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Request creation error: %v", err)
		w.Write([]byte(code))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+groqAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("API request error: %v", err)
		w.Write([]byte(code))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("API error: %d", resp.StatusCode)
		w.Write([]byte(code))
		return
	}

	var groqResp GroqResponse
	if err := json.NewDecoder(resp.Body).Decode(&groqResp); err != nil {
		log.Printf("JSON decode error: %v", err)
		w.Write([]byte(code))
		return
	}

	if len(groqResp.Choices) == 0 {
		log.Printf("No choices in response")
		w.Write([]byte(code))
		return
	}

	var fixedResp FixedCodeResponse
	if err := json.Unmarshal([]byte(groqResp.Choices[0].Message.Content), &fixedResp); err != nil {
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
