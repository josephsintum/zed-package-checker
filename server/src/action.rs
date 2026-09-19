//! The upgrade quick fix.
//!
//! A finding already knows what to upgrade to: `Matcher::fix_for` computes the
//! lowest published version no advisory on the package still affects. What it
//! does not know is *where the version is written*, because `reconcile` keeps
//! only the name span and drops the manifest sighting outright once a lockfile
//! supersedes it.
//!
//! So the span is not carried through the pipeline at all. This module reparses
//! the one file the action is being offered on — parsers are pure and cost
//! microseconds — and reads the span straight off the sighting. Nothing
//! upstream has to change, and the text parsed is the buffer the user is
//! looking at rather than whatever was last saved.

use crate::extract::parser_for;
use crate::model::{Finding, Fix, Range};
use crate::span::{Encoding, column};
use std::path::Path;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, CodeActionResponse,
    Diagnostic, DocumentChanges, NumberOrString, OneOf, OptionalVersionedTextDocumentIdentifier,
    TextDocumentEdit, TextEdit, WorkspaceEdit,
};

/// One quick fix per finding in range that has a version to upgrade to and a
/// place to write it.
pub fn upgrades(
    path: &Path,
    source: &str,
    document_version: Option<i32>,
    findings: &[Finding],
    params: &CodeActionParams,
    encoding: Encoding,
) -> CodeActionResponse {
    let Some(parse) = parser_for(path) else {
        return Vec::new();
    };
    let sightings = parse(source, path);
    let lines: Vec<&str> = source.lines().collect();

    findings
        .iter()
        .filter_map(|finding| {
            let Fix::Clears(target) = &finding.fix else {
                // `Partial` and `None` name nothing to upgrade to. Offering a
                // guess here would be worse than offering nothing.
                return None;
            };
            let diagnostic = selects(params, finding)?;
            let span = crate::extract::version_span(&sightings, finding)?;

            Some(CodeActionOrCommand::CodeAction(CodeAction {
                title: title(finding, target, path),
                kind: Some(CodeActionKind::QUICKFIX),
                diagnostics: diagnostic.map(|d| vec![d.clone()]),
                edit: Some(edit(
                    params,
                    document_version,
                    span,
                    target,
                    &lines,
                    encoding,
                )),
                is_preferred: Some(true),
                ..Default::default()
            }))
        })
        .collect()
}

type LspRange = tower_lsp_server::ls_types::Range;

/// Whether the client is asking about this finding, and its own diagnostic for
/// it if it sent one.
///
/// Matched on the advisory id wherever the client sends `context.diagnostics`,
/// which is what it is for: a finding's own range came from the file on disk,
/// so comparing positions goes wrong in exactly the case the buffer is being
/// edited. Falls back to the cursor's line for a client that sends nothing.
fn selects<'a>(params: &'a CodeActionParams, finding: &Finding) -> Option<Option<&'a Diagnostic>> {
    let ours: Vec<&Diagnostic> = params
        .context
        .diagnostics
        .iter()
        .filter(|d| d.source.as_deref() == Some(crate::config::NAME))
        .collect();
    if ours.is_empty() {
        let anchor = finding.anchor_site().range;
        let asked = params.range;
        let touches = asked.start.line <= anchor.end.line && anchor.start.line <= asked.end.line;
        return touches.then_some(None);
    }
    let worst = finding.worst();
    ours.into_iter()
        .find(|d| matches!(&d.code, Some(NumberOrString::String(id)) if *id == *worst.id))
        .map(Some)
}

fn title(finding: &Finding, target: &str, path: &Path) -> String {
    let name = finding.package.name();
    // The version was pinned in a lockfile, so editing the manifest alone
    // leaves the lockfile saying something else. Said in the title rather than
    // discovered afterwards.
    if finding.evidence.path != finding.anchor_site().path {
        let file = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "the manifest".to_owned());
        return format!("Update {name} to {target} in {file} (lockfile not updated)");
    }
    format!("Update {name} to {target}")
}

fn edit(
    params: &CodeActionParams,
    document_version: Option<i32>,
    span: Range,
    target: &str,
    lines: &[&str],
    encoding: Encoding,
) -> WorkspaceEdit {
    // Versioned where the buffer is tracked: a client whose document has moved
    // on rejects the edit rather than applying it to text we never saw.
    let document = OptionalVersionedTextDocumentIdentifier {
        uri: params.text_document.uri.clone(),
        version: document_version,
    };
    WorkspaceEdit {
        document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
            text_document: document,
            edits: vec![OneOf::Left(TextEdit {
                range: to_lsp(span, lines, encoding),
                new_text: target.to_owned(),
            })],
        }])),
        ..Default::default()
    }
}

/// A byte-column span as the client counts columns, the way `diagnostics` does.
fn to_lsp(span: Range, lines: &[&str], encoding: Encoding) -> LspRange {
    let convert = |p: crate::model::Position| {
        let character = match lines.get(p.line as usize) {
            Some(line) => column(line, p.column as usize, encoding),
            None => p.column,
        };
        tower_lsp_server::ls_types::Position::new(p.line, character)
    };
    LspRange {
        start: convert(span.start),
        end: convert(span.end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Advisory, Anchor, Ecosystem, Package, Site};
    use std::sync::Arc;
    use tower_lsp_server::ls_types::{
        CodeActionContext, PartialResultParams, TextDocumentIdentifier, Uri, WorkDoneProgressParams,
    };

    const MANIFEST: &str = "{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.0\"\n  },\n  \"devDependencies\": {\n    \"left-pad\": \"1.0.0\"\n  }\n}\n";

    fn uri() -> Uri {
        "file:///p/package.json".parse().expect("uri")
    }

    /// The finding the extractor would produce for `lodash` in [`MANIFEST`],
    /// anchored where the real parser puts it rather than at a guessed range.
    fn finding(name: &str, fix: Fix) -> Finding {
        let sighting = crate::manifest::package_json(MANIFEST, Path::new("/p/package.json"))
            .into_iter()
            .find(|s| s.package.name() == name)
            .expect("sample names it");
        Finding {
            package: Package::new(Ecosystem::Npm, name, "4.17.15"),
            advisories: vec![Arc::new(Advisory {
                id: "GHSA-1".into(),
                aliases: Box::default(),
                summary: Box::default(),
                cvss_score: 7.2,
                cvss_vector: Box::default(),
                affected: Box::default(),
                references: Box::default(),
            })],
            evidence: sighting.evidence,
            declared: None,
            paths: Vec::new(),
            reachable: None,
            from_range: true,
            dep_groups: Vec::new(),
            fix,
        }
    }

    /// A request naming our diagnostic, which is how a real client asks.
    fn params(finding: &Finding) -> CodeActionParams {
        let anchor = finding.anchor_site().range;
        let range = LspRange {
            start: tower_lsp_server::ls_types::Position::new(
                anchor.start.line,
                anchor.start.column,
            ),
            end: tower_lsp_server::ls_types::Position::new(anchor.end.line, anchor.end.column),
        };
        CodeActionParams {
            text_document: TextDocumentIdentifier { uri: uri() },
            range,
            context: CodeActionContext {
                diagnostics: vec![Diagnostic {
                    range,
                    source: Some(crate::config::NAME.to_owned()),
                    code: Some(NumberOrString::String("GHSA-1".to_owned())),
                    ..Default::default()
                }],
                ..Default::default()
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
            partial_result_params: PartialResultParams::default(),
        }
    }

    /// Every edit an action carries, applied to the source it was computed from.
    fn applied(source: &str, action: &CodeActionOrCommand) -> String {
        let CodeActionOrCommand::CodeAction(action) = action else {
            panic!("expected an action");
        };
        let Some(DocumentChanges::Edits(edits)) = &action.edit.as_ref().unwrap().document_changes
        else {
            panic!("expected document changes");
        };
        let mut out = source.to_owned();
        for edit in edits.iter().flat_map(|e| &e.edits) {
            let OneOf::Left(edit) = edit else {
                panic!("expected a plain edit");
            };
            // Byte columns, since the tests negotiate UTF-8.
            let offset = |p: tower_lsp_server::ls_types::Position| {
                source
                    .split_inclusive('\n')
                    .take(p.line as usize)
                    .map(str::len)
                    .sum::<usize>()
                    + p.character as usize
            };
            out.replace_range(
                offset(edit.range.start)..offset(edit.range.end),
                &edit.new_text,
            );
        }
        out
    }

    fn act(source: &str, findings: &[Finding], params: &CodeActionParams) -> CodeActionResponse {
        upgrades(
            Path::new("/p/package.json"),
            source,
            Some(7),
            findings,
            params,
            Encoding::Utf8,
        )
    }

    #[test]
    fn the_edit_bumps_the_version_and_leaves_the_operator_alone() {
        let f = finding("lodash", Fix::Clears("4.18.0".into()));
        let actions = act(MANIFEST, std::slice::from_ref(&f), &params(&f));
        assert_eq!(actions.len(), 1);
        assert_eq!(
            applied(MANIFEST, &actions[0]),
            MANIFEST.replace("^4.17.0", "^4.18.0")
        );
    }

    #[test]
    fn the_edited_manifest_reparses_at_the_new_version() {
        // The property that matters more than the bytes: whatever the edit
        // produced is a manifest the extractor reads back as fixed.
        let f = finding("lodash", Fix::Clears("4.18.0".into()));
        let actions = act(MANIFEST, std::slice::from_ref(&f), &params(&f));
        let after = applied(MANIFEST, &actions[0]);
        let reparsed = crate::manifest::package_json(&after, Path::new("/p/package.json"));
        let lodash = reparsed
            .iter()
            .find(|s| s.package.name() == "lodash")
            .expect("still declared");
        assert_eq!(&*lodash.package.version, "4.18.0");
        // Nothing else moved.
        let left_pad = reparsed
            .iter()
            .find(|s| s.package.name() == "left-pad")
            .expect("still declared");
        assert_eq!(&*left_pad.package.version, "1.0.0");
    }

    #[test]
    fn the_edit_names_the_document_version_it_was_computed_against() {
        let f = finding("lodash", Fix::Clears("4.18.0".into()));
        let actions = act(MANIFEST, std::slice::from_ref(&f), &params(&f));
        let CodeActionOrCommand::CodeAction(action) = &actions[0] else {
            panic!("expected an action");
        };
        let Some(DocumentChanges::Edits(edits)) = &action.edit.as_ref().unwrap().document_changes
        else {
            panic!("expected document changes");
        };
        assert_eq!(edits[0].text_document.version, Some(7));
    }

    #[test]
    fn a_finding_with_no_verified_fix_offers_nothing() {
        for fix in [Fix::Partial, Fix::None] {
            let f = finding("lodash", fix);
            assert!(act(MANIFEST, std::slice::from_ref(&f), &params(&f)).is_empty());
        }
    }

    #[test]
    fn a_lockfile_anchor_offers_nothing_because_it_is_never_rewritten() {
        let mut f = finding("lodash", Fix::Clears("4.18.0".into()));
        f.evidence = Site::new("/p/package-lock.json", crate::model::Range::whole_line(9));
        f.declared = None;
        let lock = "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"node_modules/lodash\": {\n      \"version\": \"4.17.15\"\n    }\n  }\n}\n";
        let actions = upgrades(
            Path::new("/p/package-lock.json"),
            lock,
            None,
            std::slice::from_ref(&f),
            &params(&f),
            Encoding::Utf8,
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn a_lockfile_resolved_finding_edits_the_manifest_and_says_the_lockfile_is_stale() {
        let mut f = finding("lodash", Fix::Clears("4.18.0".into()));
        let declared = f.evidence.clone();
        f.evidence = Site::new("/p/package-lock.json", crate::model::Range::whole_line(9));
        f.declared = Some(Anchor::new(declared));

        let actions = act(MANIFEST, std::slice::from_ref(&f), &params(&f));
        let CodeActionOrCommand::CodeAction(action) = &actions[0] else {
            panic!("expected an action");
        };
        assert_eq!(
            action.title,
            "Update lodash to 4.18.0 in package.json (lockfile not updated)"
        );
        assert_eq!(
            applied(MANIFEST, &actions[0]),
            MANIFEST.replace("^4.17.0", "^4.18.0")
        );
    }

    #[test]
    fn a_dirty_buffer_is_edited_where_it_now_says_the_version() {
        // The whole reason the buffer is tracked: the finding's anchor came
        // from disk, and the user has since inserted a line above it.
        let f = finding("lodash", Fix::Clears("4.18.0".into()));
        let edited = format!("\n{MANIFEST}");
        let actions = act(&edited, std::slice::from_ref(&f), &params(&f));
        assert_eq!(actions.len(), 1);
        assert_eq!(
            applied(&edited, &actions[0]),
            edited.replace("^4.17.0", "^4.18.0")
        );
    }

    #[test]
    fn a_name_in_two_sections_is_only_edited_where_it_ships() {
        // The parser attributes a package to its production section, so the
        // finding sits there and the dev declaration is left alone.
        let src = "{\n  \"dependencies\": {\n    \"lodash\": \"4.17.15\"\n  },\n  \"devDependencies\": {\n    \"lodash\": \"3.0.0\"\n  }\n}\n";
        let sightings = crate::manifest::package_json(src, Path::new("/p/package.json"));
        assert_eq!(sightings.len(), 1);

        let mut f = finding("lodash", Fix::Clears("4.18.0".into()));
        f.evidence = sightings[0].evidence.clone();
        let actions = act(src, std::slice::from_ref(&f), &params(&f));
        assert_eq!(applied(src, &actions[0]), src.replace("4.17.15", "4.18.0"));
    }

    #[test]
    fn an_unmatched_diagnostic_offers_nothing() {
        let f = finding("lodash", Fix::Clears("4.18.0".into()));
        let mut p = params(&f);
        p.context.diagnostics[0].code = Some(NumberOrString::String("GHSA-other".to_owned()));
        assert!(act(MANIFEST, std::slice::from_ref(&f), &p).is_empty());
    }

    #[test]
    fn positions_use_the_negotiated_encoding() {
        // An astral character before the version shifts the UTF-16 column but
        // not the byte one.
        let src = "{\n  \"dependencies\": {\n    \"l\u{1F980}dash\": \"1.0.0\"\n  }\n}\n";
        let sightings = crate::manifest::package_json(src, Path::new("/p/package.json"));
        let name = sightings[0].package.name().to_string();
        let mut f = finding("lodash", Fix::Clears("4.18.0".into()));
        f.package = Package::new(Ecosystem::Npm, name.as_str(), "1.0.0");
        f.evidence = sightings[0].evidence.clone();

        for encoding in [Encoding::Utf8, Encoding::Utf16] {
            let actions = upgrades(
                Path::new("/p/package.json"),
                src,
                None,
                std::slice::from_ref(&f),
                &params(&f),
                encoding,
            );
            let CodeActionOrCommand::CodeAction(action) = &actions[0] else {
                panic!("expected an action");
            };
            let Some(DocumentChanges::Edits(edits)) =
                &action.edit.as_ref().unwrap().document_changes
            else {
                panic!("expected document changes");
            };
            let OneOf::Left(edit) = &edits[0].edits[0] else {
                panic!("expected a plain edit");
            };
            let expected = match encoding {
                Encoding::Utf8 => 18,
                Encoding::Utf16 => 16,
            };
            assert_eq!(edit.range.start.character, expected, "{encoding:?}");
        }
    }
}
