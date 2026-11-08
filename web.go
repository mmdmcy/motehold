package main

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The HTTP layer, written to answer exactly as the Rust service (axum) did:
// the same statuses, headers and bodies, the same rejections for a bad path
// parameter, query or form, and empty 404 and 405 answers.

type response struct {
	status   int
	header   http.Header
	body     []byte
	rejected bool // a presented credential failed: the throttle counts it
}

func newResponse(status int, contentType string, body []byte) *response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	return &response{status: status, header: header, body: body}
}

func html(status int, body string) *response {
	return newResponse(status, "text/html; charset=utf-8", []byte(body))
}

func text(status int, body string) *response {
	return newResponse(status, "text/plain; charset=utf-8", []byte(body))
}

func empty(status int) *response { return newResponse(status, "", nil) }

func redirect(location string) *response {
	res := empty(http.StatusSeeOther)
	res.header.Set("Location", location)
	return res
}

func (r *response) cookie(value string) *response {
	r.header.Add("Set-Cookie", value)
	return r
}

func (r *response) reject() *response {
	r.rejected = true
	return r
}

func (r *response) write(w http.ResponseWriter) {
	for name, values := range r.header {
		w.Header()[name] = values
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(r.body)))
	w.WriteHeader(r.status)
	w.Write(r.body)
}

// route is one path pattern ("{id}" marks a parameter) with its handlers;
// GET also answers HEAD, as axum's get() does.
type route struct {
	pattern  []string
	handlers map[string]func(*http.Request, []string) *response
	allow    string
}

type router struct{ routes []*route }

func (rt *router) handle(pattern string, handlers map[string]func(*http.Request, []string) *response) {
	var methods []string
	for _, method := range []string{"GET", "POST"} {
		if handlers[method] != nil {
			methods = append(methods, method)
			if method == "GET" {
				methods = append(methods, "HEAD")
			}
		}
	}
	rt.routes = append(rt.routes, &route{
		pattern:  strings.Split(strings.TrimPrefix(pattern, "/"), "/"),
		handlers: handlers,
		allow:    strings.Join(methods, ","),
	})
}

// match finds the most specific route for a raw path: a static segment
// wins over a parameter at the first place they differ. Parameters come
// back percent-decoded.
func (rt *router) match(rawPath string) (*route, []string) {
	segments := strings.Split(strings.TrimPrefix(rawPath, "/"), "/")
	var best *route
	var bestParams []string
	for _, candidate := range rt.routes {
		if len(candidate.pattern) != len(segments) {
			continue
		}
		var params []string
		ok := true
		for i, part := range candidate.pattern {
			if part == "{id}" {
				// matchit takes an empty segment as a parameter, except
				// at the end of the path.
				if segments[i] == "" && i == len(segments)-1 {
					ok = false
					break
				}
				params = append(params, percentDecode(segments[i]))
			} else if part != segments[i] {
				ok = false
				break
			}
		}
		if ok && (best == nil || moreSpecific(candidate, best)) {
			best, bestParams = candidate, params
		}
	}
	return best, bestParams
}

func moreSpecific(a, b *route) bool {
	for i := range a.pattern {
		aParam, bParam := a.pattern[i] == "{id}", b.pattern[i] == "{id}"
		if aParam != bParam {
			return bParam
		}
	}
	return false
}

func (rt *router) serve(r *http.Request) *response {
	found, params := rt.match(r.URL.EscapedPath())
	if found == nil {
		return empty(http.StatusNotFound)
	}
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	handler := found.handlers[method]
	if handler == nil {
		res := empty(http.StatusMethodNotAllowed)
		res.header.Set("Allow", found.allow)
		return res
	}
	return handler(r, params)
}

// pathInt64 is axum's Path<i64>: a value that does not parse is a 400.
func pathInt64(value string) (int64, *response) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, text(http.StatusBadRequest, fmt.Sprintf("Invalid URL: Cannot parse `%s` to a `i64`", value))
	}
	return n, nil
}

// formValues is a parsed application/x-www-form-urlencoded body or query.
type formValues map[string][]string

// parseURLEncoded is the form_urlencoded parser serde_urlencoded uses:
// '+' is a space, a bad percent escape stays as it is, and invalid UTF-8
// becomes U+FFFD.
func parseURLEncoded(raw string) formValues {
	values := formValues{}
	for _, piece := range strings.Split(raw, "&") {
		if piece == "" {
			continue
		}
		name, value, _ := strings.Cut(piece, "=")
		name = lossyUTF8(percentDecode(strings.ReplaceAll(name, "+", " ")))
		value = lossyUTF8(percentDecode(strings.ReplaceAll(value, "+", " ")))
		values[name] = append(values[name], value)
	}
	return values
}

func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			out = append(out, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

// lossyUTF8 replaces each invalid byte with U+FFFD.
func lossyUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString("�")
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// optional reads a field that may be absent; twice is serde's "duplicate
// field".
func (f formValues) optional(name string) (string, bool, error) {
	values := f[name]
	switch len(values) {
	case 0:
		return "", false, nil
	case 1:
		return values[0], true, nil
	default:
		return "", false, fmt.Errorf("duplicate field `%s`", name)
	}
}

func (f formValues) required(name string) (string, *response) {
	value, present, err := f.optional(name)
	if err == nil && !present {
		err = fmt.Errorf("missing field `%s`", name)
	}
	if err != nil {
		return "", text(http.StatusUnprocessableEntity, "Failed to deserialize form body: "+err.Error())
	}
	return value, nil
}

func queryRejection(err error) *response {
	return text(http.StatusBadRequest, "Failed to deserialize query string: "+err.Error())
}

// queryInt64 is an Option<i64> query field.
func queryInt64(values formValues, name string) (*int64, *response) {
	raw, present, err := values.optional(name)
	if err != nil {
		return nil, queryRejection(err)
	}
	if !present {
		return nil, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		reason := "invalid digit found in string"
		switch {
		case raw == "":
			reason = "cannot parse integer from empty string"
		case errors.Is(err, strconv.ErrRange) && strings.HasPrefix(raw, "-"):
			reason = "number too small to fit in target type"
		case errors.Is(err, strconv.ErrRange):
			reason = "number too large to fit in target type"
		}
		return nil, queryRejection(fmt.Errorf("%s: %s", name, reason))
	}
	return &n, nil
}

// readForm is axum's Form: the content type first (415), then the body
// within the size limit (413).
func readForm(r *http.Request) (formValues, *response) {
	contentType, _ := headerText(r, "Content-Type")
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return nil, text(http.StatusUnsupportedMediaType, "Form requests must have `Content-Type: application/x-www-form-urlencoded`")
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, text(http.StatusRequestEntityTooLarge, "Failed to buffer the request body: length limit exceeded")
		}
		return nil, text(http.StatusBadRequest, "Failed to buffer the request body: "+err.Error())
	}
	return parseURLEncoded(string(body)), nil
}

// multipartBoundary is multer's parse_boundary: multipart/form-data with a
// boundary, or axum's 400.
func multipartBoundary(r *http.Request) (string, *response) {
	contentType, _ := headerText(r, "Content-Type")
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return "", text(http.StatusBadRequest, "Invalid `boundary` for `multipart/form-data` request")
	}
	return params["boundary"], nil
}
