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

/// The single lifting policy that converts a localized real path back into the virtual
/// `lsp-fuzz://` form, returning `Some(new)` when it applies and `None` when the string is unchanged.
/// Both the typed [`lift_uri`] and the JSON response lifter delegate here, so there is one policy.
///
/// Two origins are recognized, workspace first:
/// - a per-input workspace/overlay file (`…/lsp-fuzz-workspace_<hash>/<rel>`) lifts to
///   `lsp-fuzz:///<rel>` — context-free, so generic/native paths lift exactly as before even if the
///   relative path starts with `sources/`;
/// - a frozen backdrop source file, recognized ONLY when a `backdrop_root` is supplied and the string
///   is under `<backdrop_root>/sources/…`, lifts to the stable, location-independent
///   `lsp-fuzz:///backdrop/sources/<rel>`. Without a backdrop root (the native path) no `sources/`
///   segment is treated as a backdrop file, so unrelated `file://…/sources/…` URIs stay untouched.
#[must_use]
pub fn lift_localized_str(uri_str: &str, backdrop_root: Option<&str>) -> Option<String> {
    // Workspace/overlay: strip up to and including the per-input directory, yielding the canonical
    // `lsp-fuzz://<rel>` form produced by `virtual_uri_for_path` (no extra leading slash).
    if let Some(index) = uri_str.find(LspInput::WORKSPACE_DIR_PREFIX) {
        let in_workspace = uri_str[index..]
            .find('/')
            .map_or(uri_str.len(), |it| it + index + 1);
        return Some(format!(
            "{}{}",
            LspInput::PROTOCOL_PREFIX,
            &uri_str[in_workspace..]
        ));
    }
    // Backdrop-source lifting is scoped to the actual backdrop root, not a bare `/sources/` segment.
    if let Some(root) = backdrop_root
        && let Some(pos) = uri_str.find(root)
        && let Some(tail) = uri_str[pos + root.len()..].strip_prefix("/sources/")
    {
        return Some(format!(
            "{}backdrop/sources/{}",
            LspInput::PROTOCOL_PREFIX,
            tail
        ));
    }
    None
}

/// Converts a localized workspace URI back into the virtual `lsp-fuzz://` form (native/diagnostics
/// path: no backdrop context).
///
/// # Panics
///
/// Panics if the reconstructed URI cannot be parsed as a valid [`Uri`].
#[must_use]
pub fn lift_uri(uri: &Uri) -> Cow<'_, Uri> {
    match lift_localized_str(uri.as_str(), None) {
        Some(lifted) => Cow::Owned(lifted.parse().unwrap()),
        None => Cow::Borrowed(uri),
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

    use super::{lift_localized_str, lift_uri, virtual_uri_for_path, workspace_uri};

    fn lift(raw: &str) -> String {
        lift_uri(&raw.parse::<Uri>().unwrap()).as_str().to_owned()
    }

    #[test]
    fn lift_uri_is_workspace_only_without_a_backdrop() {
        // A per-input overlay file (index mode) lifts via its workspace segment to the canonical
        // `lsp-fuzz://<rel>` form.
        assert_eq!(
            lift("file:///tmp/zaozi-backdrop/.lsp-fuzz-overlay/lsp-fuzz-workspace_9/main.scala"),
            "lsp-fuzz://main.scala"
        );
        // The workspace segment wins even if the relative path starts with `sources/`.
        assert_eq!(
            lift("file:///tmp/lsp-fuzz-workspace_7/sources/a/B.scala"),
            "lsp-fuzz://sources/a/B.scala"
        );
        // Without a backdrop root, a `sources/` path is NOT treated as a backdrop file — unchanged.
        assert_eq!(
            lift("file:///nix/store/abc-zaozi-backdrop/sources/rvdecoderdb/X.scala"),
            "file:///nix/store/abc-zaozi-backdrop/sources/rvdecoderdb/X.scala"
        );
    }

    #[test]
    fn backdrop_source_lifting_is_scoped_to_the_backdrop_root() {
        let backdrop = "/nix/store/abc-zaozi-backdrop";
        // A frozen backdrop source under the given root lifts to the stable virtual form.
        assert_eq!(
            lift_localized_str(
                "file:///nix/store/abc-zaozi-backdrop/sources/rvdecoderdb/X.scala",
                Some(backdrop)
            )
            .as_deref(),
            Some("lsp-fuzz://backdrop/sources/rvdecoderdb/X.scala")
        );
        // An unrelated `sources/` path NOT under the backdrop root is left unchanged.
        assert_eq!(
            lift_localized_str("file:///elsewhere/sources/Y.scala", Some(backdrop)),
            None
        );
        // Overlay/workspace precedence holds even with a backdrop root supplied.
        assert_eq!(
            lift_localized_str(
                "file:///nix/store/abc-zaozi-backdrop/.lsp-fuzz-overlay/lsp-fuzz-workspace_3/m.scala",
                Some(backdrop)
            )
            .as_deref(),
            Some("lsp-fuzz://m.scala")
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
