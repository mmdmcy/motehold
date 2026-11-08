package main

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Note and channel policy, and the handlers that use it.

const (
	defaultChannel            = "general"
	maxNoteChars              = 256 * 1024
	maxImageBytes             = 5 * 1024 * 1024
	maxAttachmentBytes        = 512 * 1024
	maxChannelChars           = 40
	maxAttachmentPreviewChars = 8 * 1024
	maxListedNotes            = 200
	// maxBodyBytes is the router's body limit: an image, a note, an
	// attachment and 1 MiB for the form around them.
	maxBodyBytes = maxImageBytes + maxNoteChars + maxAttachmentBytes + 1024*1024
)

func allowedImageType(value string) bool {
	switch value {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	}
	return false
}

func isMarkdownAttachment(fileName, contentType *string) bool {
	if fileName != nil {
		if dot := strings.LastIndexByte(*fileName, '.'); dot >= 0 {
			switch strings.ToLower((*fileName)[dot+1:]) {
			case "md", "markdown":
				return true
			}
		}
	}
	if contentType != nil {
		essence, _, _ := strings.Cut(*contentType, ";")
		switch strings.TrimSpace(essence) {
		case "text/markdown", "text/plain":
			return true
		}
	}
	return false
}

// safeAttachmentFilename keeps ASCII letters, digits, '.', '-' and '_',
// trims dots and underscores from both ends and keeps 120 characters.
func safeAttachmentFilename(value string) string {
	var b strings.Builder
	for _, ch := range value {
		if ch < 128 && (ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-' || ch == '_') {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	sanitized := strings.Trim(b.String(), "._")
	if sanitized == "" {
		return "attachment.md"
	}
	if len(sanitized) > 120 {
		sanitized = sanitized[:120]
	}
	return sanitized
}

func findChannel(d *storeData, name string) (int64, bool) {
	key := asciiLower(name)
	for _, c := range d.Channels {
		if asciiLower(c.Name) == key {
			return c.ID, true
		}
	}
	return 0, false
}

// ensureChannel finds a channel by name (ASCII case ignored) or adds it.
func ensureChannel(d *storeData, name string, now time.Time) int64 {
	if id, found := findChannel(d, name); found {
		return id
	}
	id := d.NextChannelID
	d.Channels = append(d.Channels, channel{ID: id, Name: name, CreatedAt: rfc3339(now)})
	d.NextChannelID++
	return id
}

func channelExists(d *storeData, id int64) bool {
	return slices.ContainsFunc(d.Channels, func(c channel) bool { return c.ID == id })
}

func noteByID(d *storeData, id int64) (note, bool) {
	for _, n := range d.Notes {
		if n.ID == id {
			return n, true
		}
	}
	return note{}, false
}

// listNotes is the channel's newest notes, newest first.
func (a *app) listNotes(d *storeData, channelID int64) []noteRow {
	var rows []noteRow
	name := ""
	for _, c := range d.Channels {
		if c.ID == channelID {
			name = c.Name
		}
	}
	for i := len(d.Notes) - 1; i >= 0 && len(rows) < maxListedNotes; i-- {
		n := d.Notes[i]
		if n.ChannelID != channelID {
			continue
		}
		row := noteRow{
			id: n.ID, channel: name, body: n.Body,
			hasImage: n.Image != nil, hasAttachment: n.Attachment != nil,
			attachmentName: n.AttachmentName, attachmentType: n.AttachmentType,
		}
		if n.Attachment != nil {
			p := a.store.previews[n.Attachment.SHA256]
			row.attachmentPreview, row.attachmentPreviewTruncated = &p.text, p.truncated
		}
		rows = append(rows, row)
	}
	return rows
}

func notesLocation(channelID *int64) string {
	if channelID != nil && *channelID > 0 {
		return "/notes?channel=" + strconv.FormatInt(*channelID, 10)
	}
	return "/notes"
}

func (a *app) notesPage(r *http.Request) *response {
	query := parseURLEncoded(r.URL.RawQuery)
	wanted, rejection := queryInt64(query, "channel")
	if rejection != nil {
		return rejection
	}
	if guard := a.pageGuard(r); guard != nil {
		return guard
	}
	var body string
	a.store.view(func(d *storeData) {
		channels := d.Channels
		activeID, activeName := int64(1), defaultChannel
		if len(channels) > 0 {
			activeID, activeName = channels[0].ID, channels[0].Name
		}
		for _, c := range channels {
			if wanted != nil && c.ID == *wanted {
				activeID, activeName = c.ID, c.Name
				break
			}
		}
		body = notesPage(channels, activeID, activeName, a.listNotes(d, activeID))
	})
	return html(http.StatusOK, body)
}

func (a *app) channelCreate(r *http.Request) *response {
	form, rejection := readForm(r)
	if rejection != nil {
		return rejection
	}
	rawName, rejection := form.required("name")
	if rejection != nil {
		return rejection
	}
	if guard := a.pageGuard(r); guard != nil {
		return guard
	}
	name := strings.TrimSpace(rawName)
	var channelID *int64
	if name != "" && utf8.RuneCountInString(name) <= maxChannelChars {
		var id int64
		if err := a.store.update(func(d *storeData) error {
			id = ensureChannel(d, name, time.Now())
			return nil
		}); err == nil {
			channelID = &id
		} else {
			logError("channel create", err)
		}
	}
	return redirect(notesLocation(channelID))
}

func (a *app) channelDelete(r *http.Request, params []string) *response {
	id, rejection := pathInt64(params[0])
	if rejection != nil {
		return rejection
	}
	if guard := a.pageGuard(r); guard != nil {
		return guard
	}
	err := a.store.update(func(d *storeData) error {
		if len(d.Channels) > 1 {
			// ON DELETE CASCADE: the channel's notes go with it.
			d.Channels = slices.DeleteFunc(d.Channels, func(c channel) bool { return c.ID == id })
			d.Notes = slices.DeleteFunc(d.Notes, func(n note) bool { return n.ChannelID == id })
		}
		return nil
	})
	if err != nil {
		logError("channel delete", err)
	}
	a.store.removeUnusedBlobs()
	return redirect(notesLocation(nil))
}

func (a *app) noteCreate(r *http.Request) *response {
	boundary, rejection := multipartBoundary(r)
	if rejection != nil {
		return rejection
	}
	if guard := a.pageGuard(r); guard != nil {
		return guard
	}
	var channelID *int64
	var body string
	var imageType, attachmentName, attachmentType *string
	var imageData, attachmentData []byte
	reader := multipart.NewReader(http.MaxBytesReader(nil, r.Body, maxBodyBytes), boundary)
	for {
		part, err := reader.NextRawPart()
		if err != nil {
			break
		}
		name, fileName := partNames(part)
		content, err := io.ReadAll(part)
		if err != nil {
			break
		}
		switch name {
		case "channel_id":
			if n, err := strconv.ParseInt(strings.TrimSpace(lossyUTF8(string(content))), 10, 64); err == nil {
				channelID = &n
			} else {
				channelID = nil
			}
		case "body":
			body = lossyUTF8(string(content))
		case "image", "attachment":
			contentType := partContentType(part)
			switch {
			case contentType != nil && allowedImageType(*contentType) && len(content) > 0 && len(content) <= maxImageBytes:
				imageType, imageData = contentType, content
			case isMarkdownAttachment(fileName, contentType) && len(content) > 0 && len(content) <= maxAttachmentBytes && utf8.Valid(content):
				stored := "attachment.md"
				if fileName != nil && strings.TrimSpace(*fileName) != "" {
					stored = *fileName
				}
				kind := "text/markdown; charset=utf-8"
				attachmentName, attachmentType, attachmentData = &stored, &kind, content
			}
		}
	}
	body = strings.TrimSpace(body)
	target := int64(1)
	if channelID != nil {
		target = *channelID
	}
	if (body != "" || imageData != nil || attachmentData != nil) && len(body) <= maxNoteChars {
		if err := a.addNote(target, body, imageType, imageData, attachmentName, attachmentType, attachmentData); err != nil {
			logError("note create", err)
		}
	}
	return redirect(notesLocation(&target))
}

func (a *app) addNote(channelID int64, body string, imageType *string, imageData []byte, attachmentName, attachmentType *string, attachmentData []byte) error {
	exists := false
	a.store.view(func(d *storeData) { exists = channelExists(d, channelID) })
	if !exists {
		return nil
	}
	n := note{ChannelID: channelID, Body: body, ImageType: imageType, AttachmentName: attachmentName, AttachmentType: attachmentType, CreatedAt: rfc3339(time.Now())}
	// The blobs are written under the store's lock, so a sweep never sees
	// them before the note that names them.
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	var err error
	if imageData != nil {
		if n.Image, err = a.store.putBlob(imageData); err != nil {
			return err
		}
	}
	if attachmentData != nil {
		if n.Attachment, err = a.store.putBlob(attachmentData); err != nil {
			return err
		}
	}
	if n.Attachment != nil {
		a.store.previews[n.Attachment.SHA256] = attachmentPreview(attachmentData)
	}
	return a.store.updateLocked(func(d *storeData) error {
		if !channelExists(d, channelID) {
			return nil
		}
		n.ID = d.NextNoteID
		d.NextNoteID++
		d.Notes = append(d.Notes, n)
		return nil
	})
}

func (a *app) noteDelete(r *http.Request, params []string) *response {
	id, rejection := pathInt64(params[0])
	if rejection != nil {
		return rejection
	}
	if guard := a.pageGuard(r); guard != nil {
		return guard
	}
	var channelID *int64
	err := a.store.update(func(d *storeData) error {
		if n, found := noteByID(d, id); found {
			channelID = &n.ChannelID
		}
		d.Notes = slices.DeleteFunc(d.Notes, func(n note) bool { return n.ID == id })
		return nil
	})
	if err != nil {
		logError("note delete", err)
	}
	a.store.removeUnusedBlobs()
	return redirect(notesLocation(channelID))
}

func (a *app) noteImage(r *http.Request, params []string) *response {
	id, rejection := pathInt64(params[0])
	if rejection != nil {
		return rejection
	}
	if guard := a.rawGuard(r); guard != nil {
		return guard
	}
	var found note
	ok := false
	a.store.view(func(d *storeData) { found, ok = noteByID(d, id) })
	if !ok || found.Image == nil {
		return text(http.StatusNotFound, "not found")
	}
	if found.Image.Size > maxImageBytes {
		return text(http.StatusRequestEntityTooLarge, "image too large")
	}
	content, err := a.store.readBlob(found.Image)
	if err != nil {
		logError("note image", err)
		return text(http.StatusInternalServerError, "stored file is damaged")
	}
	contentType := "application/octet-stream"
	if found.ImageType != nil {
		contentType = *found.ImageType
	}
	res := newResponse(http.StatusOK, contentType, content)
	res.header.Set("Cache-Control", "no-store")
	return res
}

func (a *app) noteAttachment(r *http.Request, params []string) *response {
	id, rejection := pathInt64(params[0])
	if rejection != nil {
		return rejection
	}
	if guard := a.rawGuard(r); guard != nil {
		return guard
	}
	var found note
	ok := false
	a.store.view(func(d *storeData) { found, ok = noteByID(d, id) })
	if !ok || found.Attachment == nil {
		return text(http.StatusNotFound, "not found")
	}
	if found.Attachment.Size > maxAttachmentBytes {
		return text(http.StatusRequestEntityTooLarge, "attachment too large")
	}
	content, err := a.store.readBlob(found.Attachment)
	if err != nil {
		logError("note attachment", err)
		return text(http.StatusInternalServerError, "stored file is damaged")
	}
	name := "attachment.md"
	if found.AttachmentName != nil {
		name = *found.AttachmentName
	}
	res := newResponse(http.StatusOK, "text/markdown; charset=utf-8", content)
	res.header.Set("Content-Disposition", `attachment; filename="`+safeAttachmentFilename(name)+`"`)
	res.header.Set("Cache-Control", "no-store")
	return res
}

// partNames reads a part's field name and file name from its
// Content-Disposition, as sent (Go's FileName() would cut directories).
func partNames(part *multipart.Part) (string, *string) {
	_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	if err != nil {
		return "", nil
	}
	var fileName *string
	if value, ok := params["filename"]; ok {
		fileName = &value
	}
	return params["name"], fileName
}

// partContentType is the part's Content-Type with its type and subtype in
// lower case, as the mime crate gave it, or nil when it does not parse.
func partContentType(part *multipart.Part) *string {
	raw := part.Header.Get("Content-Type")
	if raw == "" {
		return nil
	}
	if _, _, err := mime.ParseMediaType(raw); err != nil {
		return nil
	}
	essence, params, hasParams := strings.Cut(raw, ";")
	value := strings.ToLower(strings.TrimSpace(essence))
	if hasParams {
		value += ";" + params
	}
	return &value
}

func logError(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", what, err)
}
