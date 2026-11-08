package main

import (
	_ "embed"
	"strconv"
	"strings"
)

// The pages, byte for byte as the Rust service rendered them.

//go:embed page.css
var pageCSS string

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

func htmlEscape(value string) string { return htmlEscaper.Replace(value) }

func page(title, body string) string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<title>` + htmlEscape(title) + `</title>
<style>
` + pageCSS + `
</style>
</head>
<body>` + body + `</body>
</html>`
}

func loginBody(oidcEnabled bool, message string) string {
	organization := ""
	if oidcEnabled {
		organization = `<a class="button" href="/auth/oidc/start">Organization login</a>
  <p>Or use the local break-glass account:</p>`
	}
	errorHTML := ""
	if message != "" {
		errorHTML = `<p class="error">` + message + `</p>`
	}
	return `
<main class="login">
  <h1>Motehold</h1>
  ` + organization + `
  ` + errorHTML + `
  <form action="/login" method="post">
    <label>Local password</label>
    <input name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Local login</button>
  </form>
</main>
`
}

func authErrorBody(message string) string {
	return `<main class="login"><h1>Motehold</h1><p class="error">` + message +
		`</p><p><a href="/login">Use local break-glass login</a></p></main>`
}

// noteRow is one listed note, as the listing query returned it.
type noteRow struct {
	id                         int64
	channel, body              string
	hasImage, hasAttachment    bool
	attachmentName             *string
	attachmentType             *string
	attachmentPreview          *string
	attachmentPreviewTruncated bool
}

func notesPage(channels []channel, activeID int64, activeName string, notes []noteRow) string {
	var rail strings.Builder
	for _, c := range channels {
		activeClass := ""
		if c.ID == activeID {
			activeClass = " active"
		}
		name := htmlEscape(c.Name)
		id := strconv.FormatInt(c.ID, 10)
		remove := ""
		if len(channels) > 1 {
			remove = `<form action="/notes/channels/` + id + `/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete channel ` + name + `">x</button></form>`
		}
		rail.WriteString(`<div class="channel-row` + activeClass + `"><a class="channel-link" href="/notes?channel=` + id + `"><span>#</span>` + name + `</a>` + remove + `</div>`)
	}
	activeLabel := htmlEscape(activeName)
	var messages strings.Builder
	if len(notes) == 0 {
		messages.WriteString(`<p class="empty">No messages in #` + activeLabel + ` yet.</p>`)
	}
	for i := len(notes) - 1; i >= 0; i-- {
		messages.WriteString(noteHTML(notes[i]))
	}
	activeIDText := strconv.FormatInt(activeID, 10)
	return page("Notes", `
<nav><a href="/">Motehold</a><strong>Notes</strong><form action="/logout" method="post"><button class="ghost" type="submit">Log out</button></form></nav>
<main class="chat-shell">
  <aside class="channel-rail" aria-label="Channels">
    <div class="rail-title">Channels</div>
    <div class="channel-list">`+rail.String()+`</div>
    <details class="channel-add">
      <summary>Add channel</summary>
      <form action="/notes/channels" method="post" class="channel-form">
        <input name="name" maxlength="`+strconv.Itoa(maxChannelChars)+`" placeholder="Channel name" required>
        <button type="submit">Add</button>
      </form>
    </details>
  </aside>
  <section class="chat-pane">
    <header class="chat-head"><strong># `+activeLabel+`</strong><span>`+strconv.Itoa(len(notes))+` messages</span></header>
    <div class="message-list">`+messages.String()+`</div>
    <form action="/notes" method="post" enctype="multipart/form-data" class="composer">
      <input name="channel_id" type="hidden" value="`+activeIDText+`">
      <textarea name="body" maxlength="`+strconv.Itoa(maxNoteChars)+`" placeholder="Message #`+activeLabel+`"></textarea>
      <label class="file-pill"><input name="attachment" type="file" accept="image/png,image/jpeg,image/gif,image/webp,.md,.markdown,text/markdown,text/plain"><span>Attach file</span></label>
      <button type="submit">Send</button>
    </form>
  </section>
</main>
<script>
const messages = document.querySelector(".message-list");
if (messages) {
  const scrollToLatest = () => {
    messages.scrollTop = messages.scrollHeight;
  };
  requestAnimationFrame(scrollToLatest);
  window.addEventListener("load", scrollToLatest);
}
const attachmentInput = document.querySelector(".file-pill input");
const attachmentLabel = document.querySelector(".file-pill span");
if (attachmentInput && attachmentLabel) {
  const defaultLabel = attachmentLabel.textContent;
  attachmentInput.addEventListener("change", () => {
    const file = attachmentInput.files && attachmentInput.files[0];
    attachmentLabel.textContent = file ? file.name : defaultLabel;
  });
}
document.querySelectorAll("[data-copy-note]").forEach((button) => {
  button.addEventListener("click", async () => {
    const originalLabel = button.textContent;
    let copied = false;
    button.disabled = true;
    try {
      const message = button.closest(".message");
      const body = message?.querySelector(".message-text")?.textContent || "";
      const attachmentUrl = button.getAttribute("data-copy-attachment") || "";
      let attachment = "";
      if (attachmentUrl) {
        const response = await fetch(attachmentUrl, {cache: "no-store"});
        if (!response.ok) throw new Error("attachment fetch failed");
        attachment = await response.text();
      }
      const text = [body, attachment].filter((value) => value.length > 0).join("\n\n");
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        copied = true;
      } else {
        const fallback = document.createElement("textarea");
        fallback.value = text;
        fallback.setAttribute("readonly", "");
        fallback.style.position = "fixed";
        fallback.style.opacity = "0";
        document.body.appendChild(fallback);
        fallback.select();
        try { copied = document.execCommand("copy"); } catch (_) {}
        fallback.remove();
      }
    } catch (_) {}
    button.textContent = copied ? "Copied" : "Copy failed";
    window.setTimeout(() => {
      button.textContent = originalLabel;
      button.disabled = false;
    }, 1400);
  });
});
</script>
`)
}

func noteHTML(n noteRow) string {
	id := strconv.FormatInt(n.id, 10)
	body := ""
	if strings.TrimSpace(n.body) != "" {
		body = `<p class="message-text">` + htmlEscape(n.body) + `</p>`
	}
	image := ""
	if n.hasImage {
		image = `<img class="message-image" src="/notes/images/` + id + `" alt="">`
	}
	attachment := ""
	if n.hasAttachment {
		name := "attachment.md"
		if n.attachmentName != nil {
			name = *n.attachmentName
		}
		kind := "File"
		if n.attachmentType != nil && strings.HasPrefix(*n.attachmentType, "text/") {
			kind = "Markdown"
		}
		notice := ""
		if n.attachmentPreviewTruncated {
			notice = `<p class="attachment-preview-note">Preview truncated. Download the file to read the rest.</p>`
		}
		previewHTML := ""
		if n.attachmentPreview != nil {
			previewHTML = `<details class="attachment-preview"><summary>Preview file</summary><pre>` + htmlEscape(*n.attachmentPreview) + `</pre>` + notice + `</details>`
		}
		attachment = `<div class="message-attachment"><a class="attachment-link" href="/notes/attachments/` + id + `" download><span class="attachment-name">` + htmlEscape(name) + `</span><span class="attachment-kind">` + kind + ` · download</span></a>` + previewHTML + `</div>`
	}
	copyButton := ""
	if strings.TrimSpace(n.body) != "" || n.hasAttachment {
		attribute := ""
		if n.hasAttachment {
			attribute = ` data-copy-attachment="/notes/attachments/` + id + `"`
		}
		copyButton = `<button type="button" class="ghost copy-button" data-copy-note` + attribute + `>Copy</button>`
	}
	return `<article class="message">
  <div class="message-avatar">#</div>
  <div class="message-body">
    <div class="message-meta"><strong>` + htmlEscape(n.channel) + `</strong><div class="message-actions">` + copyButton + `<form action="/notes/` + id + `/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete message">x</button></form></div></div>
    ` + body + image + attachment + `
  </div>
</article>`
}
