//! File picking: the XDG desktop portal first (`org.freedesktop.portal.FileChooser`, which on
//! Plasma and GNOME is the desktop's own dialog and works from a sandbox), `rfd` as a fallback
//! when no portal answers.

use std::path::{Path, PathBuf};

/// Open-file dialog with one glob filter (`*.p12 *.pfx`) labelled `filter_label`.
pub(crate) async fn pick(
    title: &str,
    filter_label: &str,
    globs: &[String],
    start_dir: Option<&Path>,
) -> Option<PathBuf> {
    match portal(title, filter_label, globs, start_dir).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("file chooser portal unavailable ({e}); falling back to rfd");
            fallback(title, filter_label, globs, start_dir).await
        }
    }
}

async fn portal(
    title: &str,
    filter_label: &str,
    globs: &[String],
    start_dir: Option<&Path>,
) -> Result<Option<PathBuf>, ashpd::Error> {
    use ashpd::desktop::file_chooser::{FileFilter, SelectedFiles};
    let mut filter = FileFilter::new(filter_label);
    for g in globs {
        filter = filter.glob(g);
    }
    let mut req = SelectedFiles::open_file()
        .title(title)
        .modal(true)
        .multiple(false)
        .filter(filter);
    if let Some(dir) = start_dir {
        req = req.current_folder(dir)?;
    }
    let response = match req.send().await?.response() {
        Ok(r) => r,
        Err(ashpd::Error::Response(ashpd::desktop::ResponseError::Cancelled)) => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(response
        .uris()
        .first()
        .and_then(|u| file_uri_to_path(u.as_str())))
}

async fn fallback(
    title: &str,
    filter_label: &str,
    globs: &[String],
    start_dir: Option<&Path>,
) -> Option<PathBuf> {
    let exts: Vec<String> = globs
        .iter()
        .map(|g| {
            g.trim_start_matches("*.")
                .trim_start_matches('*')
                .to_string()
        })
        .filter(|e| !e.is_empty())
        .collect();
    let mut dialog = rfd::AsyncFileDialog::new().set_title(title);
    if !exts.is_empty() {
        dialog = dialog.add_filter(filter_label, &exts);
    }
    if let Some(dir) = start_dir {
        dialog = dialog.set_directory(dir);
    }
    dialog.pick_file().await.map(|h| h.path().to_path_buf())
}

/// `file:///home/u/key%20a.p12` → `/home/u/key a.p12`.
fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    // Strip an authority part (`file://localhost/x`); a path always starts with `/`.
    let path = match rest.find('/') {
        Some(0) => rest,
        Some(i) => &rest[i..],
        None => return None,
    };
    let mut out = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&path[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    use std::os::unix::ffi::OsStringExt;
    Some(PathBuf::from(std::ffi::OsString::from_vec(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_decoding() {
        assert_eq!(
            file_uri_to_path("file:///home/u/key%20a.p12"),
            Some(PathBuf::from("/home/u/key a.p12"))
        );
        assert_eq!(
            file_uri_to_path("file://localhost/tmp/x.p12"),
            Some(PathBuf::from("/tmp/x.p12"))
        );
        assert_eq!(
            file_uri_to_path("file:///%D0%BA.p12"),
            Some(PathBuf::from("/к.p12"))
        );
        assert_eq!(file_uri_to_path("file:///a%2"), Some(PathBuf::from("/a%2")));
        assert_eq!(file_uri_to_path("http://x/"), None);
    }
}
