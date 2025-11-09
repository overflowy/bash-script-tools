package main

import (
	"bytes"
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
)

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

	port := getEnvOrDefault("PORT", "8080")
	log.Printf("Server starting on http://localhost:%s", port)
	log.Printf("Using shfmt: %s", shfmtPath)
	log.Printf("Using shellcheck: %s", shellcheckPath)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("index.html"))
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

	var currentLine int
	for _, line := range lines {
		// Extract line number
		if lineMatch := lineRegex.FindStringSubmatch(line); lineMatch != nil && len(lineMatch) >= 2 {
			if num, err := strconv.Atoi(lineMatch[1]); err == nil {
				currentLine = num
			}
		}

		// Extract error code and message
		if scMatch := scCodeRegex.FindStringSubmatch(line); scMatch != nil && currentLine > 0 && len(scMatch) >= 4 {
			lineErrors[currentLine] = append(lineErrors[currentLine], LineError{
				Code:     scMatch[1],
				Severity: scMatch[2],
				Message:  scMatch[3],
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
		for _, err := range errors {
			if err.Severity == "error" {
				annotationType = "error"
				break
			} else if err.Severity == "warning" && annotationType != "error" {
				annotationType = "warning"
			}
		}

		// Build combined error message with one line per issue
		var messages []string
		for _, err := range errors {
			messages = append(messages, fmt.Sprintf("%s: %s", err.Code, err.Message))
		}

		annotations = append(annotations, Annotation{
			Row:    lineNum - 1, // Ace uses 0-based indexing
			Column: 0,
			Text:   strings.Join(messages, "\n"),
			Type:   annotationType,
		})
	}

	return annotations
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
	formatted = regexp.MustCompile(`\(error\)`).ReplaceAllString(formatted, `<span class="text-red-400">(error)</span>`)
	formatted = regexp.MustCompile(`\(warning\)`).ReplaceAllString(formatted, `<span class="text-yellow-400">(warning)</span>`)
	formatted = regexp.MustCompile(`\(info\)`).ReplaceAllString(formatted, `<span class="text-blue-400">(info)</span>`)
	formatted = regexp.MustCompile(`\(style\)`).ReplaceAllString(formatted, `<span class="text-green-400">(style)</span>`)

	// Color line numbers (now just "Line X:")
	formatted = regexp.MustCompile(`(?m)^Line (\d+):`).ReplaceAllString(formatted, `<span class="text-cyan-400">Line $1:</span>`)

	return fmt.Sprintf(`<pre class="text-sm whitespace-pre-wrap font-mono">%s</pre>`, formatted)
}
