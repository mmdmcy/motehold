package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// The note store: standard library only, no database. The records live in
// one JSON file whose first line names the format and the SHA-256 of the
// rest; images and attachments live beside it in a folder, one file per
// content, named by its SHA-256. A file whose checksum, JSON or rules do not
// hold is refused, never repaired. A change writes a new file beside the old
// one (0600), syncs it, renames it over the old one and syncs the folder, so
// the file is always one whole version. The service holds an exclusive lock
// on a companion .lock file while it runs, so two processes never share a
// store.

const storeFormat = "katteke.motehold.store.v1"

type channel struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// blobRef names a file in the blob folder by its content.
type blobRef struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type note struct {
	ID             int64    `json:"id"`
	ChannelID      int64    `json:"channel_id"`
	Body           string   `json:"body"`
	ImageType      *string  `json:"image_type"`
	Image          *blobRef `json:"image"`
	AttachmentName *string  `json:"attachment_name"`
	AttachmentType *string  `json:"attachment_type"`
	Attachment     *blobRef `json:"attachment"`
	CreatedAt      string   `json:"created_at"`
	ImportSource   *string  `json:"import_source"`
}

type session struct {
	TokenHash  string `json:"token_hash"`
	AuthMethod string `json:"auth_method"`
	ExpiresAt  int64  `json:"expires_at"`
}

type pendingFlow struct {
	StateHash    string `json:"state_hash"`
	FlowHash     string `json:"flow_hash"`
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkce_verifier"`
	ExpiresAt    int64  `json:"expires_at"`
}

// storeData is everything Motehold keeps. Slices are in id order.
type storeData struct {
	Channels      []channel     `json:"channels"`
	Notes         []note        `json:"notes"`
	Sessions      []session     `json:"sessions"`
	PendingFlows  []pendingFlow `json:"pending_flows"`
	NextChannelID int64         `json:"next_channel_id"`
	NextNoteID    int64         `json:"next_note_id"`
}

type storeHeader struct {
	Format string `json:"format"`
	SHA256 string `json:"sha256"`
}

// preview is the start of an attachment shown in the channel, computed from
// the blob when the store opens and when a note is added.
type preview struct {
	text      string
	truncated bool
}

type store struct {
	path     string
	blobDir  string
	lockFile *os.File

	mu       sync.Mutex
	data     *storeData
	previews map[string]preview
}

// storePaths turns MOTEHOLD_DB into the store's paths: the same folder and
// name with .json for the records and .blobs for the files, so the setting
// keeps its Rust value (data/motehold.sqlite becomes data/motehold.json and
// data/motehold.blobs/).
func storePaths(db string) (string, string) {
	base := strings.TrimSuffix(db, filepath.Ext(db))
	if base == "" || strings.HasSuffix(base, "/") {
		base = db
	}
	return base + ".json", base + ".blobs"
}

// openStore takes the lock and reads the store, creating an empty one with
// the default channel when none is there.
func openStore(db string) (*store, error) {
	path, blobDir := storePaths(db)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &store{path: path, blobDir: blobDir}
	if err := s.lock(); err != nil {
		return nil, err
	}
	data, err := s.load()
	if errors.Is(err, os.ErrNotExist) {
		data = &storeData{NextChannelID: 1, NextNoteID: 1}
		err = nil
	}
	if err != nil {
		s.close()
		return nil, err
	}
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		s.close()
		return nil, err
	}
	previews, err := s.checkBlobs(data)
	if err != nil {
		s.close()
		return nil, err
	}
	s.data, s.previews = data, previews
	// The Rust service made sure of the default channel at every start.
	if _, found := findChannel(data, defaultChannel); !found {
		if err := s.update(func(d *storeData) error {
			ensureChannel(d, defaultChannel, time.Now())
			return nil
		}); err != nil {
			s.close()
			return nil, err
		}
	}
	s.sweepBlobs()
	return s, nil
}

// lock holds the companion lock file for the life of the process.
func (s *store) lock() error {
	path := s.path + ".lock"
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("store lock must be a regular file: %s", path)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open store lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return fmt.Errorf("the store %s is in use by another process", s.path)
	}
	s.lockFile = file
	return nil
}

func (s *store) close() {
	if s.lockFile != nil {
		syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		s.lockFile.Close()
		s.lockFile = nil
	}
}

func (s *store) load() (*storeData, error) {
	info, err := os.Lstat(s.path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("store path must be a regular file: %s", s.path)
	}
	file, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	data, err := decodeStore(raw)
	if err != nil {
		return nil, fmt.Errorf("store %s is damaged and was not used: %w", s.path, err)
	}
	return data, nil
}

func decodeStore(raw []byte) (*storeData, error) {
	headerLine, body, found := bytes.Cut(raw, []byte("\n"))
	if !found {
		return nil, errors.New("no header line")
	}
	var header storeHeader
	if err := strictJSON(headerLine, &header); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	if header.Format != storeFormat {
		return nil, fmt.Errorf("unknown format %q", header.Format)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != header.SHA256 {
		return nil, errors.New("checksum does not match its contents")
	}
	var data storeData
	if err := strictJSON(body, &data); err != nil {
		return nil, err
	}
	if err := data.validate(); err != nil {
		return nil, err
	}
	return &data, nil
}

func strictJSON(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func encodeJSON(v any, indent bool) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if indent {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(v); err != nil {
		panic(err) // only plain structs are encoded
	}
	return buf.Bytes()
}

func encodeStore(data *storeData) []byte {
	body := encodeJSON(data, true)
	sum := sha256.Sum256(body)
	header := encodeJSON(storeHeader{storeFormat, hex.EncodeToString(sum[:])}, false)
	return append(header, body...)
}

// writeFileAtomic writes a new owner-only file beside path, syncs it,
// renames it over path and syncs the folder.
func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	fresh, err := os.CreateTemp(dir, "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	name := fresh.Name()
	_, err = fresh.Write(content)
	if err == nil {
		err = fresh.Chmod(0o600)
	}
	if err == nil {
		err = fresh.Sync()
	}
	if closeErr := fresh.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
		return err
	}
	if folder, err := os.Open(dir); err == nil {
		folder.Sync()
		folder.Close()
	}
	return nil
}

func (d *storeData) clone() *storeData {
	c := *d
	c.Channels = slices.Clone(d.Channels)
	c.Notes = slices.Clone(d.Notes)
	c.Sessions = slices.Clone(d.Sessions)
	c.PendingFlows = slices.Clone(d.PendingFlows)
	return &c
}

// view runs fn on the current data; fn must not keep or change it.
func (s *store) view(fn func(*storeData)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.data)
}

// update runs fn on a copy and keeps the copy only when fn succeeds, every
// rule still holds and the file is written: a failed change leaves the
// store as it was, like a rolled-back transaction.
func (s *store) update(fn func(*storeData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(fn)
}

func (s *store) updateLocked(fn func(*storeData) error) error {
	next := s.data.clone()
	if err := fn(next); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, encodeStore(next)); err != nil {
		return fmt.Errorf("failed to write store: %w", err)
	}
	s.data = next
	return nil
}

// validate is what the SQL schema enforced: primary keys, the channel name
// unique without regard to ASCII case (COLLATE NOCASE), notes pointing at a
// channel, a unique import source, the session method's CHECK and ids that
// are never reused (AUTOINCREMENT).
func (d *storeData) validate() error {
	channels := map[int64]bool{}
	names := map[string]bool{}
	lastID := int64(0)
	for _, c := range d.Channels {
		if c.ID <= lastID || c.ID >= d.NextChannelID {
			return errors.New("PRIMARY KEY constraint failed: channels.id")
		}
		key := asciiLower(c.Name)
		if names[key] {
			return errors.New("UNIQUE constraint failed: channels.name")
		}
		channels[c.ID], names[key], lastID = true, true, c.ID
	}
	sources := map[string]bool{}
	lastID = 0
	for _, n := range d.Notes {
		if n.ID <= lastID || n.ID >= d.NextNoteID {
			return errors.New("PRIMARY KEY constraint failed: notes.id")
		}
		if !channels[n.ChannelID] {
			return errors.New("FOREIGN KEY constraint failed")
		}
		if n.ImportSource != nil {
			if sources[*n.ImportSource] {
				return errors.New("UNIQUE constraint failed: notes.import_source")
			}
			sources[*n.ImportSource] = true
		}
		for _, ref := range []*blobRef{n.Image, n.Attachment} {
			if ref != nil && !validSHA256(ref.SHA256) {
				return errors.New("CHECK constraint failed: notes blob name")
			}
		}
		lastID = n.ID
	}
	tokens := map[string]bool{}
	for _, s := range d.Sessions {
		if tokens[s.TokenHash] {
			return errors.New("UNIQUE constraint failed: auth_sessions.token_hash")
		}
		if s.AuthMethod != "local" && s.AuthMethod != "oidc" {
			return errors.New("CHECK constraint failed: auth_method IN ('local', 'oidc')")
		}
		tokens[s.TokenHash] = true
	}
	states := map[string]bool{}
	for _, f := range d.PendingFlows {
		if states[f.StateHash] {
			return errors.New("UNIQUE constraint failed: oidc_pending_flows.state_hash")
		}
		states[f.StateHash] = true
	}
	if d.NextChannelID < 1 || d.NextNoteID < 1 {
		return errors.New("CHECK constraint failed: next ids")
	}
	return nil
}

// asciiLower folds A-Z only, as SQLite's NOCASE collation does.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func validSHA256(name string) bool {
	if len(name) != 64 {
		return false
	}
	for _, c := range []byte(name) {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// putBlob stores content under its SHA-256 before the record that names it
// is written; an existing file with that name and size is kept.
func (s *store) putBlob(content []byte) (*blobRef, error) {
	sum := sha256.Sum256(content)
	ref := &blobRef{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(content))}
	path := filepath.Join(s.blobDir, ref.SHA256)
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && info.Size() == ref.Size {
		return ref, nil
	}
	if err := writeFileAtomic(path, content); err != nil {
		return nil, fmt.Errorf("failed to write blob: %w", err)
	}
	return ref, nil
}

// readBlob returns a blob's content after checking its size and checksum.
func (s *store) readBlob(ref *blobRef) ([]byte, error) {
	path := filepath.Join(s.blobDir, ref.SHA256)
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, ref.Size+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	if int64(len(content)) != ref.Size || hex.EncodeToString(sum[:]) != ref.SHA256 {
		return nil, fmt.Errorf("blob %s is damaged", path)
	}
	return content, nil
}

// checkBlobs reads every blob the records name, so a missing or damaged
// file stops the service at start, and computes the attachment previews.
func (s *store) checkBlobs(data *storeData) (map[string]preview, error) {
	previews := map[string]preview{}
	for _, n := range data.Notes {
		if n.Image != nil {
			if _, err := s.readBlob(n.Image); err != nil {
				return nil, fmt.Errorf("store %s was not used: note %d: %w", s.path, n.ID, err)
			}
		}
		if n.Attachment != nil {
			content, err := s.readBlob(n.Attachment)
			if err != nil {
				return nil, fmt.Errorf("store %s was not used: note %d: %w", s.path, n.ID, err)
			}
			previews[n.Attachment.SHA256] = attachmentPreview(content)
		}
	}
	return previews, nil
}

// removeUnusedBlobs is sweepBlobs under the store's lock, after a deletion.
func (s *store) removeUnusedBlobs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepBlobs()
}

// sweepBlobs removes blob files no record names: left by a note's deletion
// or by a change that failed after its blob was written.
func (s *store) sweepBlobs() {
	used := map[string]bool{}
	for _, n := range s.data.Notes {
		if n.Image != nil {
			used[n.Image.SHA256] = true
		}
		if n.Attachment != nil {
			used[n.Attachment.SHA256] = true
		}
	}
	entries, err := os.ReadDir(s.blobDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		stale := strings.HasPrefix(name, ".") && strings.Contains(name, ".new-")
		if (validSHA256(name) && !used[name]) || stale {
			os.Remove(filepath.Join(s.blobDir, name))
		}
	}
}

// attachmentPreview is the listing's substr(CAST(data AS TEXT), 1, 8192)
// and length(...) > 8192: the first characters, and whether there are more
// (SQLite's length() stops at the first NUL).
func attachmentPreview(content []byte) preview {
	text := string(content)
	cut, count := len(text), 0
	for i := range text {
		if count == maxAttachmentPreviewChars {
			cut = i
			break
		}
		count++
	}
	length := utf8.RuneCountInString(text)
	if nul := strings.IndexByte(text, 0); nul >= 0 {
		length = utf8.RuneCountInString(text[:nul])
	}
	return preview{text: text[:cut], truncated: length > maxAttachmentPreviewChars}
}

// rfc3339 is chrono's to_rfc3339(): fractional seconds in 0, 3, 6 or 9
// digits and a +00:00 offset.
func rfc3339(t time.Time) string {
	t = t.UTC()
	return t.Format("2006-01-02T15:04:05") + fraction(t.Nanosecond()) + "+00:00"
}

func fraction(nanos int) string {
	switch {
	case nanos == 0:
		return ""
	case nanos%1_000_000 == 0:
		return fmt.Sprintf(".%03d", nanos/1_000_000)
	case nanos%1_000 == 0:
		return fmt.Sprintf(".%06d", nanos/1_000)
	default:
		return fmt.Sprintf(".%09d", nanos)
	}
}
