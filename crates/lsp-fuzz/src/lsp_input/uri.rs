use std::{borrow::Cow, path::Path, sync::LazyLock};

use lsp_types::Uri;

use super::LspInput;

pub fn root_uri() -> Uri {
    static WORKSPACE_ROOT_URI: LazyLock<lsp_types::Uri> =
        LazyLock::new(|| LspInput::PROTOCOL_PREFIX.parse().unwrap());
    WORKSPACE_ROOT_URI.clone()
}

#[must_use]
pub fn path_from_virtual_uri(uri: &Uri) -> Option<&str> {
    uri.as_str().strip_prefix(LspInput::PROTOCOL_PREFIX)
}

#[must_use]
pub fn virtual_uri_for_path(path: &Path) -> Option<Uri> {
    let path = path.to_str()?;
    format!("{}{}", LspInput::PROTOCOL_PREFIX, path)
        .parse()
        .ok()
}

/// The frozen backdrop's source directory segment (see `docs/zaozi-backdrop.md`). An index-mode
/// response URI for a backdrop source carries no per-input workspace segment, so it is lifted to a
/// stable, location-independent virtual form rooted here.
const BACKDROP_SOURCES_SEGMENT: &str = "/sources/";

/// Converts a localized response URI back into the virtual `lsp-fuzz://` form.
///
/// Two origins are recognized:
/// - a per-input workspace/overlay file (`…/lsp-fuzz-workspace_<hash>/<rel>`) lifts to
///   `lsp-fuzz:///<rel>`;
/// - a frozen backdrop source file (`…/sources/<rel>`, index mode) lifts to the stable
///   `lsp-fuzz:///backdrop/sources/<rel>` — location-independent, so index responses fit the virtual
///   workspace model instead of leaking an absolute backdrop `file://` path.
///
/// Any other URI is returned unchanged. The workspace-segment branch takes precedence, so
/// generic/native paths (always under `lsp-fuzz-workspace_`) lift exactly as before even if the
/// input workspace itself contains a `sources/` directory.
///
/// # Panics
///
/// Panics if the reconstructed URI cannot be parsed as a valid [`Uri`].
#[must_use]
pub fn lift_uri(uri: &Uri) -> Cow<'_, Uri> {
    let uri_str = uri.as_str();
    if let Some(index) = uri_str.find(LspInput::WORKSPACE_DIR_PREFIX) {
        let in_workspace = uri_str[index..]
            .find('/')
            .map_or(uri_str.len(), |it| it + index + 1);
        let lifted = format!("{}/{}", LspInput::PROTOCOL_PREFIX, &uri_str[in_workspace..]);
        Cow::Owned(lifted.parse().unwrap())
    } else if let Some(index) = uri_str.find(BACKDROP_SOURCES_SEGMENT) {
        // Keep from `sources/` onward (drop the leading '/').
        let from_sources = &uri_str[index + 1..];
        let lifted = format!("{}/backdrop/{}", LspInput::PROTOCOL_PREFIX, from_sources);
        Cow::Owned(lifted.parse().unwrap())
    } else {
        Cow::Borrowed(uri)
    }
}

#[must_use]
pub fn workspace_uri(workspace_dir: &Path) -> Option<Cow<'_, str>> {
    let workspace_dir = workspace_dir.to_str()?;
    Some(if workspace_dir.ends_with('/') {
        Cow::Borrowed(workspace_dir)
    } else {
        Cow::Owned(format!("{workspace_dir}/"))
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use lsp_types::Uri;

    use super::{lift_uri, virtual_uri_for_path, workspace_uri};

    fn lift(raw: &str) -> String {
        lift_uri(&raw.parse::<Uri>().unwrap()).as_str().to_owned()
    }

    #[test]
    fn lift_overlay_and_backdrop_source_uris() {
        // A per-input overlay file (index mode) lifts via its workspace segment.
        assert_eq!(
            lift("file:///tmp/zaozi-backdrop/.lsp-fuzz-overlay/lsp-fuzz-workspace_9/main.scala"),
            "lsp-fuzz:///main.scala"
        );
        // A frozen backdrop source file lifts to the stable, location-independent virtual form.
        assert_eq!(
            lift("file:///nix/store/abc-zaozi-backdrop/sources/rvdecoderdb/X.scala"),
            "lsp-fuzz:///backdrop/sources/rvdecoderdb/X.scala"
        );
        // The workspace segment wins even if the input workspace itself has a `sources/` dir.
        assert_eq!(
            lift("file:///tmp/lsp-fuzz-workspace_7/sources/a/B.scala"),
            "lsp-fuzz:///sources/a/B.scala"
        );
        // An unrelated URI (no workspace segment, no backdrop sources) is returned unchanged.
        assert_eq!(
            lift("file:///nix/store/scala-library/src/Predef.scala"),
            "file:///nix/store/scala-library/src/Predef.scala"
        );
    }

    #[test]
    fn create_virtual_uri_for_workspace_path() {
        let uri = virtual_uri_for_path(Path::new("src/lib.rs")).unwrap();
        assert_eq!(uri, "lsp-fuzz://src/lib.rs".parse::<Uri>().unwrap());
    }

    #[test]
    fn normalize_workspace_uri_trailing_slash() {
        assert_eq!(
            workspace_uri(Path::new("/tmp/workspace")).unwrap(),
            "/tmp/workspace/"
        );
        assert_eq!(
            workspace_uri(Path::new("/tmp/workspace/")).unwrap(),
            "/tmp/workspace/"
        );
    }
}
