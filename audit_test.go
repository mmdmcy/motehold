package main

import "testing"

// Carried over from the Rust tests: the publication audit.

func TestSecretAssignmentAllowsPlaceholders(t *testing.T) {
	token := "TOKEN"
	for _, line := range []string{token + "=", token + "=<value>", token + "=${VALUE}", "token: &str,", "client_secret: client_secret.unwrap(),"} {
		if suspiciousSecretAssignment(line) {
			t.Errorf("flagged %q", line)
		}
	}
	if !suspiciousSecretAssignment(token + "=" + "abc123") {
		t.Fatal("real value not flagged")
	}
}

func TestDetectsCGNATPrivateAddress(t *testing.T) {
	if !containsTailscaleIPv4("bind = 100." + "64.0.1") {
		t.Fatal("CGNAT address missed")
	}
	if containsTailscaleIPv4("bind = 127.0.0.1") {
		t.Fatal("loopback flagged")
	}
}

func TestRejectsPrivatePaths(t *testing.T) {
	if auditPath(".env") == "" || auditPath("data/motehold.sqlite") == "" || auditPath("motehold.json") != "" {
		t.Fatal("paths")
	}
	if auditPath("main.go") != "" {
		t.Fatal("source flagged")
	}
}
