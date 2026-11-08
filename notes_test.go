package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// Carried over from the Rust tests: note policy and the listing's preview.

func TestMarkdownAttachmentAcceptsMDFilesAndTextTypes(t *testing.T) {
	if !isMarkdownAttachment(ptr("README.MD"), nil) || !isMarkdownAttachment(nil, ptr("text/markdown; charset=utf-8")) ||
		!isMarkdownAttachment(nil, ptr("text/plain")) {
		t.Fatal("markdown refused")
	}
	if isMarkdownAttachment(ptr("photo.png"), ptr("image/png")) {
		t.Fatal("image taken as markdown")
	}
}

func TestAttachmentFilenameIsSafeForResponseHeaders(t *testing.T) {
	if got := safeAttachmentFilename("../meeting notes.md"); got != "meeting_notes.md" {
		t.Fatal(got)
	}
	if got := safeAttachmentFilename("..."); got != "attachment.md" {
		t.Fatal(got)
	}
	if got := safeAttachmentFilename("é" + strings.Repeat("a", 200)); len(got) != 120 || got[0] != 'a' {
		t.Fatal(got)
	}
}

func TestNoteListingCapsAttachmentPreviewButPreservesFullDownload(t *testing.T) {
	a := testApp(t, false)
	attachment := strings.Repeat("é", maxAttachmentPreviewChars+64)
	if err := a.addNote(1, "", nil, nil, ptr("notes.md"), ptr("text/markdown; charset=utf-8"), []byte(attachment)); err != nil {
		t.Fatal(err)
	}
	var rows []noteRow
	a.store.view(func(d *storeData) { rows = a.listNotes(d, 1) })
	if len(rows) != 1 || utf8.RuneCountInString(*rows[0].attachmentPreview) != maxAttachmentPreviewChars || !rows[0].attachmentPreviewTruncated {
		t.Fatal(rows)
	}
	stored, err := a.store.readBlob(a.store.data.Notes[0].Attachment)
	if err != nil || string(stored) != attachment {
		t.Fatal(err)
	}
}

// New: a whole note with an image goes in through the form and comes back
// out byte for byte.

func TestANoteWithAnImageRoundTrips(t *testing.T) {
	a := testApp(t, false)
	cookie := sessionCookieFrom(t, call(a, "POST", "/login", formType, "password=secret"))
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("channel_id", "1")
	w.WriteField("body", "  look  ")
	part, _ := w.CreatePart(map[string][]string{"Content-Disposition": {`form-data; name="attachment"; filename="a.png"`}, "Content-Type": {"image/png"}})
	part.Write([]byte("\x89PNG pixels"))
	w.Close()
	r := call(a, "POST", "/notes", w.FormDataContentType(), body.String(), "Cookie", cookie)
	if r.status != http.StatusSeeOther || r.header.Get("Location") != "/notes?channel=1" {
		t.Fatal(r.status, r.header)
	}
	image := call(a, "GET", "/notes/images/1", "", "", "Cookie", cookie)
	if image.status != http.StatusOK || image.body != "\x89PNG pixels" || image.header.Get("Content-Type") != "image/png" || image.header.Get("Cache-Control") != "no-store" {
		t.Fatal(image)
	}
	page := call(a, "GET", "/", "", "", "Cookie", cookie)
	if !strings.Contains(page.body, `<p class="message-text">look</p><img class="message-image" src="/notes/images/1" alt="">`) {
		t.Fatal(page.body)
	}
}
