use axum::response::{Html, IntoResponse, Response};

use crate::{
    features::notes::{MAX_CHANNEL_CHARS, MAX_NOTE_CHARS},
    persistence::notes::{ChannelRow, NoteRow},
};

const PAGE_CSS: &str = include_str!("page.css");

pub(crate) fn login_body(oidc_enabled: bool, error: Option<&str>) -> String {
    let organization = if oidc_enabled {
        r#"<a class="button" href="/auth/oidc/start">Organization login</a>
  <p>Or use the local break-glass account:</p>"#
    } else {
        ""
    };
    let error = error
        .map(|message| format!(r#"<p class="error">{message}</p>"#))
        .unwrap_or_default();
    format!(
        r#"
<main class="login">
  <h1>Motehold</h1>
  {organization}
  {error}
  <form action="/login" method="post">
    <label>Local password</label>
    <input name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">Local login</button>
  </form>
</main>
"#
    )
}

pub(crate) fn auth_error_body(message: &str) -> String {
    format!(
        r#"<main class="login"><h1>Motehold</h1><p class="error">{message}</p><p><a href="/login">Use local break-glass login</a></p></main>"#
    )
}

pub(crate) fn notes_page(
    channels: &[ChannelRow],
    active_channel_id: i64,
    active_channel_name: &str,
    notes: &[NoteRow],
) -> Response {
    let channels_html = channels
        .iter()
        .map(|channel| {
            let active_class = if channel.id == active_channel_id {
                " active"
            } else {
                ""
            };
            let channel_name = html_escape(&channel.name);
            let delete = if channels.len() > 1 {
                format!(
                    r#"<form action="/notes/channels/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete channel {}">x</button></form>"#,
                    channel.id, channel_name
                )
            } else {
                String::new()
            };
            format!(
                r##"<div class="channel-row{active_class}"><a class="channel-link" href="/notes?channel={}"><span>#</span>{}</a>{}</div>"##,
                channel.id, channel_name, delete
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let active_channel_label = html_escape(active_channel_name);
    let notes_html = if notes.is_empty() {
        format!(
            r##"<p class="empty">No messages in #{} yet.</p>"##,
            active_channel_label
        )
    } else {
        notes
            .iter()
            .rev()
            .map(|note| {
                let body = if note.body.trim().is_empty() {
                    String::new()
                } else {
                    format!(r#"<p class="message-text">{}</p>"#, html_escape(&note.body))
                };
                let image = if note.has_image {
                    format!(
                        r#"<img class="message-image" src="/notes/images/{}" alt="">"#,
                        note.id
                    )
                } else {
                    String::new()
                };
                let attachment = if note.has_attachment {
                    let name = note
                        .attachment_name
                        .as_deref()
                        .unwrap_or("attachment.md");
                    let kind = if note
                        .attachment_type
                        .as_deref()
                        .is_some_and(|value| value.starts_with("text/"))
                    {
                        "Markdown"
                    } else {
                        "File"
                    };
                    let preview_notice = if note.attachment_preview_truncated {
                        r#"<p class="attachment-preview-note">Preview truncated. Download the file to read the rest.</p>"#
                    } else {
                        ""
                    };
                    let preview = note
                        .attachment_preview
                        .as_deref()
                        .map(|text| {
                            format!(
                                r#"<details class="attachment-preview"><summary>Preview file</summary><pre>{}</pre>{preview_notice}</details>"#,
                                html_escape(text),
                            )
                        })
                        .unwrap_or_default();
                    format!(
                        r##"<div class="message-attachment"><a class="attachment-link" href="/notes/attachments/{}" download><span class="attachment-name">{}</span><span class="attachment-kind">{} · download</span></a>{}</div>"##,
                        note.id,
                        html_escape(name),
                        kind,
                        preview
                    )
                } else {
                    String::new()
                };
                let copy_button = if note.body.trim().is_empty() && !note.has_attachment {
                    String::new()
                } else {
                    let attachment_attribute = if note.has_attachment {
                        format!(
                            r#" data-copy-attachment="/notes/attachments/{}""#,
                            note.id
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        r#"<button type="button" class="ghost copy-button" data-copy-note{attachment_attribute}>Copy</button>"#
                    )
                };
                format!(
                    r##"<article class="message">
  <div class="message-avatar">#</div>
  <div class="message-body">
    <div class="message-meta"><strong>{}</strong><div class="message-actions">{}<form action="/notes/{}/delete" method="post"><button class="icon danger-icon" type="submit" aria-label="Delete message">x</button></form></div></div>
    {}{}{}
  </div>
</article>"##,
                    html_escape(&note.channel),
                    copy_button,
                    note.id,
                    body,
                    image,
                    attachment
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let message_count = notes.len();
    page(
        "Notes",
        &format!(
            r#"
<nav><a href="/">Motehold</a><strong>Notes</strong><form action="/logout" method="post"><button class="ghost" type="submit">Log out</button></form></nav>
<main class="chat-shell">
  <aside class="channel-rail" aria-label="Channels">
    <div class="rail-title">Channels</div>
    <div class="channel-list">{channels_html}</div>
    <details class="channel-add">
      <summary>Add channel</summary>
      <form action="/notes/channels" method="post" class="channel-form">
        <input name="name" maxlength="{MAX_CHANNEL_CHARS}" placeholder="Channel name" required>
        <button type="submit">Add</button>
      </form>
    </details>
  </aside>
  <section class="chat-pane">
    <header class="chat-head"><strong># {active_channel_label}</strong><span>{message_count} messages</span></header>
    <div class="message-list">{notes_html}</div>
    <form action="/notes" method="post" enctype="multipart/form-data" class="composer">
      <input name="channel_id" type="hidden" value="{active_channel_id}">
      <textarea name="body" maxlength="{MAX_NOTE_CHARS}" placeholder="Message #{active_channel_label}"></textarea>
      <label class="file-pill"><input name="attachment" type="file" accept="image/png,image/jpeg,image/gif,image/webp,.md,.markdown,text/markdown,text/plain"><span>Attach file</span></label>
      <button type="submit">Send</button>
    </form>
  </section>
</main>
<script>
const messages = document.querySelector(".message-list");
if (messages) {{
  const scrollToLatest = () => {{
    messages.scrollTop = messages.scrollHeight;
  }};
  requestAnimationFrame(scrollToLatest);
  window.addEventListener("load", scrollToLatest);
}}
const attachmentInput = document.querySelector(".file-pill input");
const attachmentLabel = document.querySelector(".file-pill span");
if (attachmentInput && attachmentLabel) {{
  const defaultLabel = attachmentLabel.textContent;
  attachmentInput.addEventListener("change", () => {{
    const file = attachmentInput.files && attachmentInput.files[0];
    attachmentLabel.textContent = file ? file.name : defaultLabel;
  }});
}}
document.querySelectorAll("[data-copy-note]").forEach((button) => {{
  button.addEventListener("click", async () => {{
    const originalLabel = button.textContent;
    let copied = false;
    button.disabled = true;
    try {{
      const message = button.closest(".message");
      const body = message?.querySelector(".message-text")?.textContent || "";
      const attachmentUrl = button.getAttribute("data-copy-attachment") || "";
      let attachment = "";
      if (attachmentUrl) {{
        const response = await fetch(attachmentUrl, {{cache: "no-store"}});
        if (!response.ok) throw new Error("attachment fetch failed");
        attachment = await response.text();
      }}
      const text = [body, attachment].filter((value) => value.length > 0).join("\n\n");
      if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        copied = true;
      }} else {{
        const fallback = document.createElement("textarea");
        fallback.value = text;
        fallback.setAttribute("readonly", "");
        fallback.style.position = "fixed";
        fallback.style.opacity = "0";
        document.body.appendChild(fallback);
        fallback.select();
        try {{ copied = document.execCommand("copy"); }} catch (_) {{}}
        fallback.remove();
      }}
    }} catch (_) {{}}
    button.textContent = copied ? "Copied" : "Copy failed";
    window.setTimeout(() => {{
      button.textContent = originalLabel;
      button.disabled = false;
    }}, 1400);
  }});
}});
</script>
"#
        ),
    )
}

pub(crate) fn page(title: &str, body: &str) -> Response {
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
<title>{}</title>
<style>
{PAGE_CSS}
</style>
</head>
<body>{}</body>
</html>"#,
        html_escape(title),
        body
    ))
    .into_response()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn login_html_preserves_managed_and_break_glass_choices() {
        let managed = login_body(true, Some("Wrong password."));
        assert!(managed.contains("Organization login"));
        assert!(managed.contains("Local login"));
        assert!(managed.contains("Wrong password."));

        let local = login_body(false, None);
        assert!(!local.contains("Organization login"));
        assert!(local.contains("Local login"));
    }

    #[tokio::test]
    async fn notes_html_preserves_routes_and_empty_channel_copy() {
        let channels = [ChannelRow {
            id: 1,
            name: "general".into(),
        }];
        let response = notes_page(&channels, 1, "general", &[]);
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("No messages in #general yet."));
        assert!(body.contains(r#"action="/notes/channels""#));
        assert!(body.contains(r#"action="/notes""#));
        assert!(body.contains(r#"action="/logout""#));
        assert!(body.contains("[data-copy-note]"));
    }
}
