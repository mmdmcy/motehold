//! Note and channel policy.
//!
//! Entry points are the upload limits and validation functions used by the HTTP
//! interface. This capability does not depend on application infrastructure.

pub(crate) const DEFAULT_CHANNEL: &str = "general";
pub(crate) const MAX_NOTE_CHARS: usize = 256 * 1024;
pub(crate) const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;
pub(crate) const MAX_ATTACHMENT_BYTES: usize = 512 * 1024;
pub(crate) const MAX_CHANNEL_CHARS: usize = 40;

pub(crate) fn allowed_image_type(value: &str) -> bool {
    matches!(
        value,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    )
}

pub(crate) fn is_markdown_attachment(file_name: Option<&str>, content_type: Option<&str>) -> bool {
    let has_markdown_extension = file_name
        .and_then(|name| name.rsplit_once('.').map(|(_, extension)| extension))
        .is_some_and(|extension| {
            matches!(extension.to_ascii_lowercase().as_str(), "md" | "markdown")
        });
    let is_markdown_type = content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| matches!(value.trim(), "text/markdown" | "text/plain"));
    has_markdown_extension || is_markdown_type
}

pub(crate) fn safe_attachment_filename(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches(|ch: char| ch == '.' || ch == '_');
    if sanitized.is_empty() {
        "attachment.md".into()
    } else {
        sanitized.chars().take(120).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_attachment_accepts_md_files_and_text_types() {
        assert!(is_markdown_attachment(Some("README.MD"), None));
        assert!(is_markdown_attachment(
            None,
            Some("text/markdown; charset=utf-8")
        ));
        assert!(is_markdown_attachment(None, Some("text/plain")));
        assert!(!is_markdown_attachment(
            Some("photo.png"),
            Some("image/png")
        ));
    }

    #[test]
    fn attachment_filename_is_safe_for_response_headers() {
        assert_eq!(
            safe_attachment_filename("../meeting notes.md"),
            "meeting_notes.md"
        );
        assert_eq!(safe_attachment_filename("..."), "attachment.md");
    }
}
