package main

import "net/http"

// The unauthenticated status envelope for local service discovery: no
// notes, attachment metadata, database paths, credentials or identity
// endpoints.

type componentStatusData struct {
	Status       string   `json:"status"`
	Version      string   `json:"version"`
	Standalone   bool     `json:"standalone"`
	IdentityMode string   `json:"identity_mode"`
	Capabilities []string `json:"capabilities"`
}

type componentStatusEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	Component     string              `json:"component"`
	Operation     string              `json:"operation"`
	Outcome       string              `json:"outcome"`
	Data          componentStatusData `json:"data"`
	Warnings      []string            `json:"warnings"`
	Error         *string             `json:"error"`
	CorrelationID string              `json:"correlation_id"`
}

func (a *app) componentStatus(r *http.Request) *response {
	envelope := componentStatusEnvelope{
		SchemaVersion: "linuxmice.response.v1",
		Component:     "katteke.motehold",
		Operation:     "status",
		Outcome:       "success",
		Data: componentStatusData{
			Status: "ready", Version: version, Standalone: true,
			IdentityMode: a.auth.identityMode(),
			Capabilities: []string{"notes.channels", "notes.attachments", "notes.images"},
		},
		Warnings:      []string{},
		CorrelationID: requestCorrelationID(r),
	}
	body := encodeJSON(envelope, false)
	return newResponse(http.StatusOK, "application/json", body[:len(body)-1])
}

// requestCorrelationID echoes a safe X-Correlation-Id (1 to 128 of
// [A-Za-z0-9-_.:]) and otherwise makes a random one.
func requestCorrelationID(r *http.Request) string {
	if value, ok := headerText(r, "X-Correlation-Id"); ok && value != "" && len(value) <= 128 {
		safe := true
		for _, c := range []byte(value) {
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
				safe = false
				break
			}
		}
		if safe {
			return value
		}
	}
	return randomToken()
}
