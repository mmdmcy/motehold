package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// audit-public: checks the files Git would publish for private paths,
// common secret markers, Tailscale/CGNAT addresses and local denylist
// terms, before anything is pushed.

type auditFinding struct {
	path    string
	line    int // 0: the path itself
	message string
}

func auditPublicCmd(args []string) (int, error) {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			fmt.Print(`Usage:
  motehold audit-public
  motehold audit-public --install-hook

Checks tracked files for local/private paths, common secret markers,
private-network IP leaks, and host-specific denylist terms.

`)
			return 0, nil
		}
	}
	root, err := gitRoot()
	if err != nil {
		return 0, err
	}
	for _, arg := range args {
		if arg == "--install-hook" {
			if err := installAuditHooks(root); err != nil {
				return 0, err
			}
			fmt.Println("installed .git/hooks/pre-commit and .git/hooks/pre-push")
			break
		}
	}
	findings, err := auditPublic(root)
	if err != nil {
		return 0, err
	}
	if len(findings) == 0 {
		fmt.Println("audit-public: ok")
		return 0, nil
	}
	fmt.Fprintf(os.Stderr, "audit-public: found %d issue(s)\n", len(findings))
	for _, f := range findings {
		if f.line > 0 {
			fmt.Fprintf(os.Stderr, "%s:%d: %s\n", f.path, f.line, f.message)
		} else {
			fmt.Fprintf(os.Stderr, "%s: %s\n", f.path, f.message)
		}
	}
	return 1, nil
}

func gitRoot() (string, error) {
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", errors.New("not inside a Git repository")
	}
	return strings.TrimSpace(string(output)), nil
}

func installAuditHooks(root string) error {
	hooks := filepath.Join(root, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"pre-commit", "pre-push"} {
		hook := filepath.Join(hooks, name)
		script := "#!/bin/sh\nset -eu\nrepo_root=$(git rev-parse --show-toplevel)\ncd \"$repo_root\"\ngo run . audit-public\n"
		if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
			return err
		}
		if err := os.Chmod(hook, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func auditPublic(root string) ([]auditFinding, error) {
	files, err := gitPublishableFiles(root)
	if err != nil {
		return nil, err
	}
	terms := loadAuditDenylist(root)
	var findings []auditFinding
	for _, path := range files {
		if message := auditPath(path); message != "" {
			findings = append(findings, auditFinding{path: path, message: message})
			continue
		}
		full := filepath.Join(root, path)
		if info, err := os.Stat(full); err == nil && info.Size() > 1_000_000 {
			continue
		}
		raw, err := os.ReadFile(full)
		if err != nil || !utf8.Valid(raw) {
			continue
		}
		for i, line := range textLines(string(raw)) {
			for _, message := range auditLine(line, terms) {
				findings = append(findings, auditFinding{path: path, line: i + 1, message: message})
			}
		}
	}
	return findings, nil
}

// textLines is Rust's str::lines(): split on \n, drop a trailing \r, no
// empty last line.
func textLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSuffix(line, "\r")
	}
	return lines
}

func gitPublishableFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.New(strings.TrimSpace(stderr.String()))
	}
	var files []string
	for _, path := range strings.Split(string(output), "\x00") {
		if path != "" {
			files = append(files, path)
		}
	}
	return files, nil
}

func auditPath(path string) string {
	normalized := strings.ReplaceAll(path, `\`, "/")
	name := normalized[strings.LastIndexByte(normalized, '/')+1:]
	for _, denied := range []string{"AGENTS.md", "motehold.local.toml", ".env", ".env.local", "id_rsa", "id_ed25519"} {
		if normalized == denied || name == denied {
			return "private file path is tracked"
		}
	}
	if strings.HasPrefix(name, ".env.") && name != ".env.example" {
		return "private env file is tracked"
	}
	for _, prefix := range []string{"docs/private/", ".motehold/", "backups/", "data/", "downloads/"} {
		if strings.HasPrefix(normalized, prefix) {
			return "ignored private/runtime path is tracked"
		}
	}
	for _, part := range []string{"/data/", "/cache/", "/config/", "/downloads/", "/secrets/"} {
		if strings.Contains(normalized, part) {
			return "runtime or secret data path is tracked"
		}
	}
	switch rustExtension(name) {
	case "db", "sqlite", "sqlite3", "log", "pid", "pem", "key", "p12", "pfx":
		return "private state or key-like file is tracked"
	}
	return ""
}

// rustExtension is Path::extension(): the part after the last dot, unless
// the name starts with its only dot.
func rustExtension(name string) string {
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 {
		return ""
	}
	return name[dot+1:]
}

func loadAuditDenylist(root string) []string {
	paths := []string{
		filepath.Join(root, "docs/private/audit-denylist.txt"),
		filepath.Join(root, ".motehold/audit-denylist.txt"),
	}
	if path, ok := os.LookupEnv("MOTEHOLD_AUDIT_DENYLIST"); ok {
		paths = append(paths, path)
	}
	var terms []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil || !utf8.Valid(raw) {
			continue
		}
		for _, line := range textLines(string(raw)) {
			term := strings.TrimSpace(line)
			if term == "" || strings.HasPrefix(term, "#") {
				continue
			}
			terms = append(terms, asciiLower(term))
		}
	}
	return terms
}

func auditLine(line string, terms []string) []string {
	var findings []string
	lower := asciiLower(line)
	if strings.HasPrefix(strings.TrimLeftFunc(line, unicode.IsSpace), "#") {
		return findings
	}
	if strings.Contains(line, "-----BEGIN ") && strings.Contains(line, "PRIVATE"+" KEY") {
		findings = append(findings, "private key material")
	}
	for _, marker := range tokenMarkers() {
		if strings.Contains(line, marker) {
			findings = append(findings, fmt.Sprintf("token marker `%s`", marker))
		}
	}
	if containsTailscaleIPv4(line) {
		findings = append(findings, "Tailscale/CGNAT private IP address")
	}
	if suspiciousSecretAssignment(line) {
		findings = append(findings, "non-placeholder secret-looking assignment")
	}
	for _, term := range terms {
		if term != "" && strings.Contains(lower, term) {
			findings = append(findings, "local denylist term")
		}
	}
	return findings
}

func tokenMarkers() []string {
	return []string{
		"github" + "_pat_", "gh" + "p_", "gh" + "o_", "gh" + "s_", "gh" + "u_",
		"s" + "k-", "xo" + "xb-", "xo" + "xp-",
	}
}

func suspiciousSecretAssignment(line string) bool {
	if strings.Contains(line, "::") {
		return false
	}
	key, value, found := strings.Cut(line, "=")
	if !found {
		key, value, found = strings.Cut(line, ":")
	}
	if !found {
		return false
	}
	key = asciiLower(strings.TrimSpace(key))
	if key == "" || len(key) > 80 {
		return false
	}
	for _, c := range []byte(key) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	named := false
	for _, needle := range []string{"password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "client_secret", "private_key"} {
		named = named || strings.Contains(key, needle)
	}
	if !named {
		return false
	}
	value = strings.TrimSpace(strings.TrimRight(strings.Trim(strings.Trim(strings.TrimSpace(value), `"`), "'"), ","))
	switch asciiLower(value) {
	case "", "example", "placeholder", "changeme", "change-me", "redacted", "dummy", "none", "null", "false", "true":
		return false
	}
	if value == "String" || value == "&str" || strings.HasPrefix(value, "Option<") || strings.HasPrefix(value, "Vec<") ||
		strings.HasPrefix(value, key+".") || strings.Contains(value, `"placeholder"`) {
		return false
	}
	if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "<") || strings.HasPrefix(value, "your-") ||
		strings.Contains(value, "...") || strings.HasPrefix(value, "Some(") || strings.HasPrefix(value, "vec!") {
		return false
	}
	return true
}

func containsTailscaleIPv4(line string) bool {
	tokens := strings.FieldsFunc(line, func(c rune) bool { return !(c >= '0' && c <= '9' || c == '.') })
	for _, token := range tokens {
		if strings.Count(token, ".") != 3 {
			continue
		}
		var octets []int
		for _, part := range strings.Split(token, ".") {
			if n, err := strconv.ParseUint(part, 10, 16); err == nil {
				octets = append(octets, int(n))
			}
		}
		if len(octets) != 4 || octets[0] != 100 || octets[1] < 64 || octets[1] > 127 {
			continue
		}
		valid := true
		for _, octet := range octets {
			valid = valid && octet <= 255
		}
		if valid {
			return true
		}
	}
	return false
}
