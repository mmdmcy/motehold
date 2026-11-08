package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"unicode/utf8"
)

// import-sqlite: the one-time move from the Rust service's SQLite database.
// Channels and notes come over with their ids, times, images and
// attachments as they were; the id counters continue where SQLite's
// AUTOINCREMENT stood. Sessions and pending sign-ins are short-lived and
// stay behind: people sign in again. The database is read with the
// system's sqlite3 command, read-only and immutable (meant for a copy,
// never the live file). Only counts are printed.

const sqliteSchemaVersion = 3

type sqliteReader struct{ uri string }

func newSQLiteReader(path string) (*sqliteReader, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file (a copy of the database)", path)
	}
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return nil, errors.New("the sqlite3 command is missing; install it (apt install sqlite3)")
	}
	escaped := (&url.URL{Path: path}).EscapedPath()
	return &sqliteReader{uri: "file:" + escaped + "?mode=ro&immutable=1"}, nil
}

// rows runs one query and decodes its JSON rows into out.
func (r *sqliteReader) rows(query string, out any) error {
	cmd := exec.Command("sqlite3", "-readonly", "-json", r.uri, query)
	cmd.Env = append(os.Environ(), "SQLITE_HISTORY=/dev/null")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("sqlite3 failed: %s", strings.TrimSpace(stderr.String()))
	}
	text := strings.TrimSpace(string(output))
	if text == "" {
		text = "[]"
	}
	return json.Unmarshal([]byte(text), out)
}

func importSQLiteCmd(args []string) error {
	flags := flag.NewFlagSet("import-sqlite", flag.ContinueOnError)
	from := flags.String("from", "", "a copy of the Rust service's database")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *from == "" || flags.NArg() > 0 {
		return errors.New("usage: motehold import-sqlite --from COPY (the store goes where MOTEHOLD_DB points, as .json)")
	}
	db, ok := os.LookupEnv("MOTEHOLD_DB")
	if !ok {
		db = "data/motehold.sqlite"
	}
	counts, err := importSQLite(db, *from)
	if err != nil {
		return err
	}
	os.Stdout.Write(encodeJSON(counts, false))
	return nil
}

type importCounts struct {
	Store       string `json:"store"`
	Channels    int    `json:"channels"`
	Notes       int    `json:"notes"`
	Images      int    `json:"images"`
	Attachments int    `json:"attachments"`
	Dropped     struct {
		Sessions     int `json:"sessions"`
		PendingFlows int `json:"pending_flows"`
	} `json:"dropped"`
}

func importSQLite(db, from string) (*importCounts, error) {
	path, blobDir := storePaths(db)
	if err := os.MkdirAll(blobDir, 0o700); err != nil {
		return nil, err
	}
	s := &store{path: path, blobDir: blobDir}
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.close()
	if _, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("refused to overwrite the store at %s", path)
	}
	reader, err := newSQLiteReader(from)
	if err != nil {
		return nil, err
	}
	var version []struct {
		Version *int `json:"version"`
	}
	if err := reader.rows("SELECT MAX(version) AS version FROM schema_migrations", &version); err != nil {
		return nil, err
	}
	if len(version) != 1 || version[0].Version == nil || *version[0].Version != sqliteSchemaVersion {
		return nil, fmt.Errorf("%s is not a schema-%d Motehold database", from, sqliteSchemaVersion)
	}
	data, counts, err := readSQLite(reader, s)
	if err != nil {
		return nil, fmt.Errorf("import from %s failed: %w", from, err)
	}
	if err := data.validate(); err != nil {
		return nil, fmt.Errorf("import from %s failed: %w", from, err)
	}
	if err := writeFileAtomic(path, encodeStore(data)); err != nil {
		return nil, err
	}
	counts.Store = path
	return counts, nil
}

func readSQLite(r *sqliteReader, s *store) (*storeData, *importCounts, error) {
	data := &storeData{NextChannelID: 1, NextNoteID: 1}
	counts := &importCounts{}
	var channels []channel
	if err := r.rows("SELECT id, name, created_at FROM channels ORDER BY id", &channels); err != nil {
		return nil, nil, err
	}
	data.Channels = channels
	var notes []struct {
		ID             int64   `json:"id"`
		ChannelID      int64   `json:"channel_id"`
		Body           string  `json:"body"`
		ImageType      *string `json:"image_type"`
		ImageHex       *string `json:"image_hex"`
		AttachmentName *string `json:"attachment_name"`
		AttachmentType *string `json:"attachment_type"`
		AttachmentHex  *string `json:"attachment_hex"`
		CreatedAt      string  `json:"created_at"`
		ImportSource   *string `json:"import_source"`
	}
	query := "SELECT id, channel_id, body, image_type, " +
		"CASE WHEN image_data IS NULL THEN NULL ELSE hex(image_data) END AS image_hex, " +
		"attachment_name, attachment_type, " +
		"CASE WHEN attachment_data IS NULL THEN NULL ELSE hex(attachment_data) END AS attachment_hex, " +
		"created_at, import_source FROM notes ORDER BY id"
	if err := r.rows(query, &notes); err != nil {
		return nil, nil, err
	}
	for _, row := range notes {
		n := note{
			ID: row.ID, ChannelID: row.ChannelID, Body: row.Body, ImageType: row.ImageType,
			AttachmentName: row.AttachmentName, AttachmentType: row.AttachmentType,
			CreatedAt: row.CreatedAt, ImportSource: row.ImportSource,
		}
		if row.ImageHex != nil {
			content, err := hex.DecodeString(*row.ImageHex)
			if err != nil {
				return nil, nil, fmt.Errorf("note %d: unreadable image", row.ID)
			}
			if n.Image, err = s.putBlob(content); err != nil {
				return nil, nil, err
			}
			counts.Images++
		}
		if row.AttachmentHex != nil {
			content, err := hex.DecodeString(*row.AttachmentHex)
			if err != nil {
				return nil, nil, fmt.Errorf("note %d: unreadable attachment", row.ID)
			}
			if !utf8.Valid(content) {
				return nil, nil, fmt.Errorf("note %d: the attachment is not UTF-8 text", row.ID)
			}
			if n.Attachment, err = s.putBlob(content); err != nil {
				return nil, nil, err
			}
			counts.Attachments++
		}
		data.Notes = append(data.Notes, n)
	}
	var sequences []struct {
		Name string `json:"name"`
		Seq  int64  `json:"seq"`
	}
	if err := r.rows("SELECT name, seq FROM sqlite_sequence", &sequences); err != nil {
		return nil, nil, err
	}
	for _, seq := range sequences {
		switch seq.Name {
		case "channels":
			data.NextChannelID = max(data.NextChannelID, seq.Seq+1)
		case "notes":
			data.NextNoteID = max(data.NextNoteID, seq.Seq+1)
		}
	}
	for _, c := range data.Channels {
		data.NextChannelID = max(data.NextChannelID, c.ID+1)
	}
	for _, n := range data.Notes {
		data.NextNoteID = max(data.NextNoteID, n.ID+1)
	}
	var dropped []struct {
		Sessions int `json:"sessions"`
		Flows    int `json:"flows"`
	}
	if err := r.rows("SELECT (SELECT COUNT(*) FROM auth_sessions) AS sessions, (SELECT COUNT(*) FROM oidc_pending_flows) AS flows", &dropped); err != nil {
		return nil, nil, err
	}
	if len(dropped) == 1 {
		counts.Dropped.Sessions, counts.Dropped.PendingFlows = dropped[0].Sessions, dropped[0].Flows
	}
	counts.Channels, counts.Notes = len(data.Channels), len(data.Notes)
	return data, counts, nil
}
