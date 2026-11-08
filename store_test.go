package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The Rust migration tests become store tests: a new store has the default
// channel, damage is refused, a failed change leaves nothing behind, and
// the one-time import brings a schema-3 database over.

func TestNewStoreHasTheDefaultChannelOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "motehold.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	st.view(func(d *storeData) {
		if len(d.Channels) != 1 || d.Channels[0].Name != "general" || len(d.Notes) != 0 {
			t.Fatal(d.Channels)
		}
	})
	if info, err := os.Stat(filepath.Join(dir, "motehold.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal(err, info)
	}
}

func TestStoreKeepsNotesAcrossARestart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "motehold.sqlite")
	st, err := openStore(db)
	if err != nil {
		t.Fatal(err)
	}
	a := newApp(testAuthConfig(t, false), st)
	if err := a.addNote(1, "keep me", nil, nil, ptr("n.md"), ptr("text/markdown; charset=utf-8"), []byte("# hi")); err != nil {
		t.Fatal(err)
	}
	st.close()
	again, err := openStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer again.close()
	again.view(func(d *storeData) {
		if len(d.Notes) != 1 || d.Notes[0].Body != "keep me" || d.Notes[0].ID != 1 || d.NextNoteID != 2 {
			t.Fatal(d.Notes)
		}
	})
	if p := again.previews[again.data.Notes[0].Attachment.SHA256]; p.text != "# hi" {
		t.Fatal(p)
	}
}

func TestDamagedStoreIsRefusedNotRepaired(t *testing.T) {
	db := filepath.Join(t.TempDir(), "motehold.sqlite")
	st, err := openStore(db)
	if err != nil {
		t.Fatal(err)
	}
	st.close()
	path, _ := storePaths(db)
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(raw, []byte(`"general"`), []byte(`"generaL"`), 1), 0o600)
	if _, err := openStore(db); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if bytes.Equal(after, raw) {
		t.Fatal("the damaged file was rewritten")
	}
}

func TestDamagedBlobIsRefusedAtStart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "motehold.sqlite")
	st, _ := openStore(db)
	a := newApp(testAuthConfig(t, false), st)
	a.addNote(1, "", ptr("image/png"), []byte("png bytes"), nil, nil, nil)
	ref := st.data.Notes[0].Image
	st.close()
	os.WriteFile(filepath.Join(st.blobDir, ref.SHA256), []byte("png bytez"), 0o600)
	if _, err := openStore(db); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Fatal(err)
	}
}

func TestTheStoreIsUsedByOneProcessAtATime(t *testing.T) {
	db := filepath.Join(t.TempDir(), "motehold.sqlite")
	st, err := openStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if _, err := openStore(db); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatal(err)
	}
}

func TestAFailedChangeLeavesNothingBehind(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "motehold.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	before, _ := os.ReadFile(st.path)
	err = st.update(func(d *storeData) error {
		d.Channels = append(d.Channels, channel{ID: d.NextChannelID, Name: "GENERAL"})
		d.NextChannelID++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed: channels.name") {
		t.Fatal(err)
	}
	err = st.update(func(d *storeData) error {
		d.Notes = append(d.Notes, note{ID: d.NextNoteID, ChannelID: 99})
		d.NextNoteID++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Fatal(err)
	}
	if st.update(func(*storeData) error { return errors.New("stop") }) == nil {
		t.Fatal("error lost")
	}
	after, _ := os.ReadFile(st.path)
	if !bytes.Equal(before, after) || len(st.data.Channels) != 1 || len(st.data.Notes) != 0 {
		t.Fatal("a failed change was kept")
	}
}

func TestDeletingAChannelTakesItsNotesAndUnusedBlobs(t *testing.T) {
	a := testApp(t, false)
	var id int64
	a.store.update(func(d *storeData) error { id = ensureChannel(d, "work", time.Now()); return nil })
	a.addNote(id, "", ptr("image/gif"), []byte("GIF89a"), nil, nil, nil)
	cookie := sessionCookieFrom(t, call(a, "POST", "/login", formType, "password=secret"))
	call(a, "POST", "/notes/channels/2/delete", "", "", "Cookie", cookie)
	if len(a.store.data.Notes) != 0 || len(a.store.data.Channels) != 1 {
		t.Fatal(a.store.data)
	}
	entries, _ := os.ReadDir(a.store.blobDir)
	if len(entries) != 0 {
		t.Fatal("blob kept", entries)
	}
	// The last channel is never deleted.
	call(a, "POST", "/notes/channels/1/delete", "", "", "Cookie", cookie)
	if len(a.store.data.Channels) != 1 {
		t.Fatal("last channel deleted")
	}
}

func TestStorePathsKeepTheSetting(t *testing.T) {
	for db, want := range map[string]string{
		"/opt/x/services/motehold/motehold.sqlite": "/opt/x/services/motehold/motehold.json",
		"data/motehold.sqlite":                     "data/motehold.json",
		"motehold":                                 "motehold.json",
		"store.json":                               "store.json",
	} {
		if got, _ := storePaths(db); got != want {
			t.Errorf("%s: %s", db, got)
		}
	}
}

// TestImportFromASchema3Database builds a database with the Rust service's
// schema through the system's sqlite3 and imports it.
func TestImportFromASchema3Database(t *testing.T) {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		t.Skip("sqlite3 is not installed")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "rust.sqlite")
	schema := `
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));
INSERT INTO schema_migrations (version) VALUES (1), (2), (3);
CREATE TABLE channels (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL COLLATE NOCASE UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, channel_id INTEGER NOT NULL, body TEXT NOT NULL, image_type TEXT, image_data BLOB,
  created_at TEXT NOT NULL, import_source TEXT UNIQUE, attachment_name TEXT, attachment_type TEXT, attachment_data BLOB,
  FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE);
CREATE TABLE auth_sessions (token_hash TEXT PRIMARY KEY, auth_method TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE oidc_pending_flows (state_hash TEXT PRIMARY KEY, flow_hash TEXT NOT NULL, nonce TEXT NOT NULL, pkce_verifier TEXT NOT NULL, expires_at INTEGER NOT NULL);
INSERT INTO channels (name, created_at) VALUES ('general', '2026-07-18T19:53:00+00:00'), ('gone', 'x'), ('work', '2026-07-19T10:00:00.5+00:00');
DELETE FROM channels WHERE name = 'gone';
INSERT INTO notes (channel_id, body, created_at, import_source) VALUES (1, 'hello & <you>', '2026-07-18T20:00:00+00:00', 'legacy:1');
INSERT INTO notes (channel_id, body, image_type, image_data, created_at) VALUES (3, '', 'image/png', X'89504E470D0A1A0A', 'now');
INSERT INTO notes (channel_id, body, attachment_name, attachment_type, attachment_data, created_at) VALUES (1, '', '../a.md', 'text/markdown; charset=utf-8', CAST('# héllo' AS BLOB), 'now');
INSERT INTO notes (channel_id, body, created_at) VALUES (1, 'deleted', 'now');
DELETE FROM notes WHERE body = 'deleted';
INSERT INTO auth_sessions VALUES ('abc', 'local', 9999999999);
`
	cmd := exec.Command("sqlite3", source)
	cmd.Stdin = strings.NewReader(schema)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	db := filepath.Join(dir, "go", "motehold.sqlite")
	counts, err := importSQLite(db, source)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Channels != 2 || counts.Notes != 3 || counts.Images != 1 || counts.Attachments != 1 || counts.Dropped.Sessions != 1 {
		t.Fatalf("%+v", counts)
	}
	if _, err := importSQLite(db, source); err == nil || !strings.Contains(err.Error(), "refused to overwrite") {
		t.Fatal(err)
	}
	st, err := openStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	d := st.data
	if d.Channels[1].ID != 3 || d.Channels[1].CreatedAt != "2026-07-19T10:00:00.5+00:00" || d.NextChannelID != 4 || d.NextNoteID != 5 {
		t.Fatalf("%+v", d)
	}
	if *d.Notes[0].ImportSource != "legacy:1" || d.Notes[0].Body != "hello & <you>" || *d.Notes[2].AttachmentName != "../a.md" || len(d.Sessions) != 0 {
		t.Fatalf("%+v", d.Notes)
	}
	image, err := st.readBlob(d.Notes[1].Image)
	if err != nil || string(image) != "\x89PNG\r\n\x1a\n" {
		t.Fatal(err)
	}
	if p := st.previews[d.Notes[2].Attachment.SHA256]; p.text != "# héllo" || p.truncated {
		t.Fatal(p)
	}
	// Anything but schema 3 is refused.
	other := filepath.Join(dir, "other.sqlite")
	cmd = exec.Command("sqlite3", other, "CREATE TABLE schema_migrations (version INTEGER); INSERT INTO schema_migrations VALUES (2);")
	cmd.Run()
	if _, err := importSQLite(filepath.Join(dir, "third", "m.sqlite"), other); err == nil || !strings.Contains(err.Error(), "schema-3") {
		t.Fatal(err)
	}
}
