//! Who is answerable for a transitive npm dependency.
//!
//! A lockfile entry carries no parent links, so the resolution npm performed
//! has to be reconstructed: [`crate::manifest::npm::Lock`] holds the install
//! paths and the names each entry asked for, and this module walks them.
//!
//! npm only. `pnpm-lock.yaml`, `yarn.lock` and `bun.lock` record different
//! structures and each needs its own builder; until one exists, their
//! transitive dependencies keep the lockfile anchoring they have today.

use crate::manifest::npm::{DepKind, Lock};
use crate::model::{Declaration, Ecosystem, PackageKey, Site};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// The most lock entries a graph is built for.
///
/// Above this the attribution is abandoned wholesale rather than truncated. A
/// partial graph does not merely omit findings, it anchors them on the wrong
/// line — which is worse than the lockfile anchoring it would have replaced.
const MAX_NODES: usize = 100_000;

/// How many distinct chains one finding reports.
///
/// The message names the first and counts the rest, so a fourth buys nothing.
const MAX_CHAINS: usize = 3;

/// What the walk saw. The graph is allowed to see nothing else, or it would
/// attribute findings to manifests the report says do not exist.
pub(crate) struct Workspace<'a> {
    /// Every `package.json` the walk read, by path.
    pub(crate) manifests: &'a HashMap<PathBuf, Vec<Declaration>>,
    /// Every directory holding a lockfile, so a member with one of its own is
    /// not claimed by the lockfile above it.
    pub(crate) lock_dirs: &'a HashSet<PathBuf>,
}

/// One lock entry, and the manifest declaration answerable for it.
#[derive(Clone, Debug)]
pub(crate) struct Attribution {
    /// Which entry of the lockfile this is about.
    pub(crate) node: usize,
    /// Where the user can act: the direct dependency that reaches it.
    pub(crate) declared: Site,
    /// root -> ... -> package, shortest first. Never empty: a package the root
    /// declares itself is left to `reconcile`, which already anchors it.
    pub(crate) paths: Vec<Vec<PackageKey>>,
}

/// An edge, once the name it names has been resolved to an entry.
#[derive(Clone, Copy)]
struct Edge {
    to: usize,
    kind: DepKind,
}

/// Which manifests a lockfile answers for, and what each of them reaches.
///
/// Returns nothing where the lockfile records no edges — a v1 file from npm
/// 5.0–5.1 — since an edgeless graph cannot be told apart from one where every
/// dependency is direct.
pub(crate) fn attribute(tree: &Lock, lock_dir: &Path, seen: &Workspace<'_>) -> Vec<Attribution> {
    if !tree.has_edges {
        tracing::debug!(
            dir = %lock_dir.display(),
            "lockfile records no dependency edges; transitive attribution unavailable"
        );
        return Vec::new();
    }
    if tree.nodes.len() > MAX_NODES {
        tracing::warn!(
            dir = %lock_dir.display(),
            nodes = tree.nodes.len(),
            max = MAX_NODES,
            "lockfile too large to attribute; transitive findings stay on their lockfile lines"
        );
        return Vec::new();
    }

    // Resolution depends only on where an entry sits and what it asked for,
    // never on which root a walk started from, so it is done once for the whole
    // tree rather than once per member.
    let adjacency = resolve_edges(tree);

    let mut out = Vec::new();
    for root in roots(tree, lock_dir, seen) {
        out.extend(reach(tree, &adjacency, &root));
    }
    // Sorted so an unchanged tree republishes an unchanged report. Node index
    // is the lockfile's own key order, and the declaration line breaks a tie
    // between two members reaching the same entry.
    out.sort_by(|a, b| {
        a.node
            .cmp(&b.node)
            .then_with(|| a.declared.path.cmp(&b.declared.path))
            .then_with(|| a.declared.range.start.line.cmp(&b.declared.range.start.line))
    });
    out
}

/// Every name every entry asked for, resolved to the entry npm would have used.
fn resolve_edges(tree: &Lock) -> Vec<Vec<Edge>> {
    tree.nodes
        .iter()
        .map(|node| {
            node.deps
                .iter()
                .filter_map(|dep| {
                    // A name that resolves to nothing is normal: an optional
                    // peer npm chose not to install, or a bundled dependency,
                    // which is not a lock key at all.
                    tree.resolve(&node.path, &dep.name).map(|to| Edge {
                        to,
                        kind: dep.kind,
                    })
                })
                .collect()
        })
        .collect()
}

/// A manifest a lockfile answers for, and where its walk begins.
struct Root {
    /// The entry in the lockfile, whose install path anchors resolution.
    node: usize,
    /// What that manifest declares.
    declarations: Vec<Declaration>,
}

/// The manifests this lockfile governs.
///
/// A root key is the empty one or a directory key, but three further conditions
/// keep out things that merely look like members:
///
/// - **No `..`.** `{"link": true, "resolved": "../shared"}` is a `file:`
///   dependency outside the tree, not a workspace member, and attributing to it
///   would publish diagnostics for a file outside the project.
/// - **The walk read its manifest.** A member excluded by the skip list, or
///   lost to the file cap, must not become a root the report says is absent.
/// - **No nearer lockfile.** A member with its own `package-lock.json` is
///   governed by that one, and claiming it here would report it twice at two
///   different versions.
fn roots(tree: &Lock, lock_dir: &Path, seen: &Workspace<'_>) -> Vec<Root> {
    let mut out = Vec::new();
    for (node, entry) in tree.nodes.iter().enumerate() {
        if entry.path.contains("node_modules/") {
            continue;
        }
        if entry.path.split('/').any(|segment| segment == "..") {
            continue;
        }
        let dir = if entry.path.is_empty() {
            lock_dir.to_path_buf()
        } else {
            lock_dir.join(&*entry.path)
        };
        if nearest_lock_dir(&dir, seen.lock_dirs).as_deref() != Some(lock_dir) {
            continue;
        }
        let Some(declarations) = seen.manifests.get(&dir.join("package.json")) else {
            continue;
        };
        out.push(Root {
            node,
            declarations: declarations.clone(),
        });
    }
    out
}

/// The directory of the nearest lockfile at or above `dir`.
fn nearest_lock_dir(dir: &Path, lock_dirs: &HashSet<PathBuf>) -> Option<PathBuf> {
    let mut at = Some(dir);
    while let Some(dir) = at {
        if lock_dirs.contains(dir) {
            return Some(dir.to_path_buf());
        }
        at = dir.parent();
    }
    None
}

/// Everything one manifest reaches, and the chain that reaches it.
fn reach(tree: &Lock, adjacency: &[Vec<Edge>], root: &Root) -> Vec<Attribution> {
    let mut found = walk(tree, adjacency, root, Peers::Excluded);
    // Peer edges are real — npm 7+ installs them — but they are a shorter route
    // than the reason a package is actually there, so `react` reached as a peer
    // of some plugin would outrank the honest chain through `react-dom`. They
    // run as a second pass over whatever nothing else reached, which needs no
    // ranking function and lets the honest chain always win.
    for extra in walk(tree, adjacency, root, Peers::Included) {
        if !found.iter().any(|seen| seen.node == extra.node) {
            found.push(extra);
        }
    }
    found
}

/// Whether a pass may traverse `peerDependencies`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Peers {
    Excluded,
    Included,
}

impl Peers {
    fn allows(self, kind: DepKind) -> bool {
        match kind {
            DepKind::Runtime => true,
            // Followed only out of the entry a walk started from, which the
            // seeding below does directly: npm installs a package's dev
            // dependencies only for the project's own packages, and strips them
            // from everything under `node_modules`.
            DepKind::Dev => false,
            DepKind::Peer => self == Peers::Included,
        }
    }
}

/// Breadth-first from one manifest, recording the first way each entry is met.
fn walk(tree: &Lock, adjacency: &[Vec<Edge>], root: &Root, peers: Peers) -> Vec<Attribution> {
    let from = &tree.nodes[root.node].path;
    let mut predecessor: Vec<Option<usize>> = vec![None; tree.nodes.len()];
    let mut alternates: Vec<Vec<usize>> = vec![Vec::new(); tree.nodes.len()];
    let mut origin: Vec<Option<usize>> = vec![None; tree.nodes.len()];
    let mut depth: Vec<u32> = vec![0; tree.nodes.len()];
    let mut seen = vec![false; tree.nodes.len()];
    let mut queue = VecDeque::new();

    // Seeded from the manifest rather than from the lock's own root entry, so
    // every branch starts at a line the user can edit. A name the lockfile
    // carries but the manifest no longer does has nowhere to anchor anything it
    // reaches, so it is left to fall back to its lockfile line.
    for (which, declaration) in root.declarations.iter().enumerate() {
        let Some(node) = tree.resolve(from, &declaration.name) else {
            continue;
        };
        if std::mem::replace(&mut seen[node], true) {
            continue;
        }
        origin[node] = Some(which);
        depth[node] = 1;
        queue.push_back(node);
    }

    while let Some(at) = queue.pop_front() {
        for edge in &adjacency[at] {
            if !peers.allows(edge.kind) {
                continue;
            }
            if !seen[edge.to] {
                seen[edge.to] = true;
                predecessor[edge.to] = Some(at);
                origin[edge.to] = origin[at];
                depth[edge.to] = depth[at] + 1;
                queue.push_back(edge.to);
            } else if depth[edge.to] == depth[at] + 1
                && predecessor[edge.to] != Some(at)
                && !alternates[edge.to].contains(&at)
                && alternates[edge.to].len() < MAX_CHAINS - 1
            {
                // Another way in, exactly as short. Recorded so the message can
                // say how many, without a second shortest-paths algorithm.
                alternates[edge.to].push(at);
            }
        }
    }

    (0..tree.nodes.len())
        .filter(|&node| seen[node] && predecessor[node].is_some())
        .filter_map(|node| {
            let declaration = &root.declarations[origin[node]?];
            let mut paths = vec![chain(tree, &predecessor, node)];
            for &alternate in &alternates[node] {
                let mut path = chain(tree, &predecessor, alternate);
                path.push(key_of(tree, node));
                paths.push(path);
            }
            Some(Attribution {
                node,
                declared: declaration.site.clone(),
                paths,
            })
        })
        .collect()
}

/// The chain from the manifest down to `node`, excluding the root and
/// including the package itself — the order [`crate::model::Finding::paths`]
/// documents.
fn chain(tree: &Lock, predecessor: &[Option<usize>], node: usize) -> Vec<PackageKey> {
    let mut back = vec![key_of(tree, node)];
    let mut at = node;
    // Bounded by the predecessor chain, which a breadth-first walk cannot make
    // cyclic, but capped anyway: this reads attacker-chosen bytes.
    while let Some(parent) = predecessor[at] {
        back.push(key_of(tree, parent));
        at = parent;
        if back.len() > MAX_NODES {
            break;
        }
    }
    back.reverse();
    back
}

fn key_of(tree: &Lock, node: usize) -> PackageKey {
    PackageKey::new(Ecosystem::Npm, &*tree.nodes[node].registry_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::npm::lock;
    use crate::model::Range;

    /// A v3 lockfile with the given `(install path, entry body)` pairs.
    fn v3(entries: &[(&str, &str)]) -> String {
        let body: Vec<String> = entries
            .iter()
            .map(|(key, entry)| format!("    {key:?}: {entry}"))
            .collect();
        format!(
            "{{\n  \"lockfileVersion\": 3,\n  \"packages\": {{\n{}\n  }}\n}}\n",
            body.join(",\n")
        )
    }

    /// Attribution over one lockfile, flattened to what a reader can check by
    /// eye: `package via a > b @ manifest:line`.
    ///
    /// `members` gives each manifest the walk read as `(directory relative to
    /// the lockfile, the names it declares)`; `""` is the root. `extra_locks`
    /// names directories that hold a lockfile of their own.
    fn attributions(src: &str, members: &[(&str, &[&str])], extra_locks: &[&str]) -> Vec<String> {
        let root = PathBuf::from("/p");
        let tree = lock(src).expect("the fixture is a lockfile");

        let mut manifests = HashMap::new();
        for (dir, names) in members {
            let at = if dir.is_empty() {
                root.clone()
            } else {
                root.join(dir)
            };
            let declarations = names
                .iter()
                .enumerate()
                .map(|(line, name)| Declaration {
                    name: (*name).into(),
                    // One per line, so two members are told apart by where
                    // they anchor and not only by which file.
                    site: Site::new(at.join("package.json"), Range::on_line(line as u32, 0, 1)),
                    groups: Vec::new(),
                })
                .collect();
            manifests.insert(at.join("package.json"), declarations);
        }

        let mut lock_dirs = HashSet::from([root.clone()]);
        lock_dirs.extend(extra_locks.iter().map(|dir| root.join(dir)));

        let seen = Workspace {
            manifests: &manifests,
            lock_dirs: &lock_dirs,
        };
        attribute(&tree, &root, &seen)
            .iter()
            .map(|found| {
                let chains: Vec<String> = found
                    .paths
                    .iter()
                    .map(|path| {
                        path.iter()
                            .map(|key| key.name.to_string())
                            .collect::<Vec<_>>()
                            .join(" > ")
                    })
                    .collect();
                format!(
                    "{} via {} @ {}:{}",
                    tree.nodes[found.node].registry_name,
                    chains.join(" | "),
                    found
                        .declared
                        .path
                        .strip_prefix(&root)
                        .unwrap_or(&found.declared.path)
                        .display(),
                    found.declared.range.start.line
                )
            })
            .collect()
    }

    #[test]
    fn a_three_deep_chain_names_every_hop() {
        let src = v3(&[
            (
                "",
                r#"{"name": "root", "dependencies": {"mkdirp": "^0.5.1"}}"#,
            ),
            (
                "node_modules/mkdirp",
                r#"{"version": "0.5.1", "dependencies": {"minipass": "^2"}}"#,
            ),
            (
                "node_modules/minipass",
                r#"{"version": "2.9.0", "dependencies": {"minimist": "^1"}}"#,
            ),
            ("node_modules/minimist", r#"{"version": "1.2.0"}"#),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["mkdirp"])], &[]),
            [
                "minipass via mkdirp > minipass @ package.json:0",
                "minimist via mkdirp > minipass > minimist @ package.json:0",
            ]
        );
    }

    #[test]
    fn a_dependency_the_manifest_declares_is_left_to_reconcile() {
        // It already anchors a direct dependency by name; a second answer here
        // would only collide with that one.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            ("node_modules/lodash", r#"{"version": "4.17.15"}"#),
        ]);
        assert!(attributions(&src, &[("", &["lodash"])], &[]).is_empty());
    }

    #[test]
    fn a_cycle_terminates() {
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"b": "1"}}"#,
            ),
            (
                "node_modules/b",
                r#"{"version": "1.0.0", "dependencies": {"a": "1"}}"#,
            ),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["a"])], &[]),
            ["b via a > b @ package.json:0"]
        );
    }

    #[test]
    fn a_nested_duplicate_is_attributed_through_the_parent_that_resolves_to_it() {
        // Two versions of one package. `a` resolves to the nested 3.0.0 and
        // must not be blamed for the hoisted 4.0.0 that `b` reaches.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"lodash": "^3"}}"#,
            ),
            ("node_modules/a/node_modules/lodash", r#"{"version": "3.0.0"}"#),
            (
                "node_modules/b",
                r#"{"version": "1.0.0", "dependencies": {"lodash": "^4"}}"#,
            ),
            ("node_modules/lodash", r#"{"version": "4.0.0"}"#),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["a", "b"])], &[]),
            [
                "lodash via a > lodash @ package.json:0",
                "lodash via b > lodash @ package.json:1",
            ]
        );
    }

    #[test]
    fn a_workspace_member_is_answerable_for_what_it_reaches() {
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "packages/api",
                r#"{"version": "1.0.0", "dependencies": {"express": "^4"}}"#,
            ),
            (
                "node_modules/api",
                r#"{"link": true, "resolved": "packages/api"}"#,
            ),
            (
                "node_modules/express",
                r#"{"version": "4.17.1", "dependencies": {"cookie": "^0.4"}}"#,
            ),
            ("node_modules/cookie", r#"{"version": "0.4.0"}"#),
        ]);
        assert_eq!(
            attributions(&src, &[("", &[]), ("packages/api", &["express"])], &[]),
            ["cookie via express > cookie @ packages/api/package.json:0"]
        );
    }

    #[test]
    fn a_file_target_outside_the_tree_is_not_a_root() {
        // `{"link": true, "resolved": "../shared"}` is a `file:` dependency,
        // not a member. Attributing to it would publish diagnostics for a
        // manifest outside the project the walk never visited.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "../shared",
                r#"{"version": "1.0.0", "dependencies": {"lodash": "^4"}}"#,
            ),
            ("node_modules/lodash", r#"{"version": "4.17.15"}"#),
        ]);
        assert!(
            attributions(&src, &[("", &[]), ("../shared", &["lodash"])], &[]).is_empty(),
            "nothing outside the lockfile's own tree may be a root"
        );
    }

    #[test]
    fn a_member_with_its_own_lockfile_is_not_claimed_by_the_root() {
        // Its own lockfile governs it; claiming it here would report the same
        // package twice, at two different versions.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "packages/app",
                r#"{"version": "1.0.0", "dependencies": {"a": "^1"}}"#,
            ),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"b": "1"}}"#,
            ),
            ("node_modules/b", r#"{"version": "1.0.0"}"#),
        ]);
        assert!(
            attributions(
                &src,
                &[("", &[]), ("packages/app", &["a"])],
                &["packages/app"],
            )
            .is_empty()
        );
    }

    #[test]
    fn a_manifest_the_walk_did_not_read_is_not_a_root() {
        // Excluded by the skip list, or lost to the file cap. The graph and the
        // report have to agree about which members exist.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "packages/api",
                r#"{"version": "1.0.0", "dependencies": {"a": "^1"}}"#,
            ),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"b": "1"}}"#,
            ),
            ("node_modules/b", r#"{"version": "1.0.0"}"#),
        ]);
        assert!(attributions(&src, &[("", &[])], &[]).is_empty());
    }

    #[test]
    fn dev_dependencies_are_followed_only_out_of_the_manifest() {
        // npm strips them from everything under `node_modules`, and a linked
        // member entered from a sibling must not lend its test tooling to the
        // sibling's production line.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "devDependencies": {"tooling": "1"}, "dependencies": {"b": "1"}}"#,
            ),
            ("node_modules/tooling", r#"{"version": "1.0.0"}"#),
            ("node_modules/b", r#"{"version": "1.0.0"}"#),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["a"])], &[]),
            ["b via a > b @ package.json:0"]
        );
    }

    #[test]
    fn a_peer_edge_only_carries_what_nothing_else_reaches() {
        // A peer edge is a shorter route than the real install reason, so the
        // honest chain through `b` has to win for `shared`.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "node_modules/plugin",
                r#"{"version": "1.0.0", "peerDependencies": {"shared": "1", "lonely": "1"}}"#,
            ),
            (
                "node_modules/b",
                r#"{"version": "1.0.0", "dependencies": {"shared": "1"}}"#,
            ),
            ("node_modules/shared", r#"{"version": "1.0.0"}"#),
            ("node_modules/lonely", r#"{"version": "1.0.0"}"#),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["plugin", "b"])], &[]),
            [
                "shared via b > shared @ package.json:1",
                "lonely via plugin > lonely @ package.json:0",
            ]
        );
    }

    #[test]
    fn an_entry_nothing_reaches_is_attributed_to_nobody() {
        // An extraneous install. It keeps its lockfile line, which is the
        // honest answer when no manifest is responsible for it.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            ("node_modules/a", r#"{"version": "1.0.0"}"#),
            ("node_modules/orphan", r#"{"version": "1.0.0"}"#),
        ]);
        assert!(attributions(&src, &[("", &["a"])], &[]).is_empty());
    }

    #[test]
    fn a_lockfile_recording_no_edges_attributes_nothing() {
        // npm 5.0-5.1. Guessing here would anchor every transitive finding on
        // whichever dependency happened to be declared first.
        let src = r#"{"dependencies": {"a": {"version": "1.0.0"}, "b": {"version": "2.0.0"}}}"#;
        assert!(attributions(src, &[("", &["a"])], &[]).is_empty());
    }

    #[test]
    fn one_parent_reaching_a_package_by_two_names_is_counted_once() {
        // `a` depends on `shared` and on an alias that links to the same entry,
        // and `q` got there first. Without a guard `a` is recorded as an
        // alternate way in twice, and the message says "2 other paths" when
        // there is only one.
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "node_modules/q",
                r#"{"version": "1.0.0", "dependencies": {"shared": "1"}}"#,
            ),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"shared": "1", "alias": "1"}}"#,
            ),
            ("node_modules/shared", r#"{"version": "1.0.0"}"#),
            (
                "node_modules/alias",
                r#"{"link": true, "resolved": "node_modules/shared"}"#,
            ),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["q", "a"])], &[]),
            ["shared via q > shared | a > shared @ package.json:0"]
        );
    }

    #[test]
    fn two_equally_short_chains_are_both_reported() {
        let src = v3(&[
            ("", r#"{"name": "root"}"#),
            (
                "node_modules/a",
                r#"{"version": "1.0.0", "dependencies": {"shared": "1"}}"#,
            ),
            (
                "node_modules/b",
                r#"{"version": "1.0.0", "dependencies": {"shared": "1"}}"#,
            ),
            ("node_modules/shared", r#"{"version": "1.0.0"}"#),
        ]);
        assert_eq!(
            attributions(&src, &[("", &["a", "b"])], &[]),
            ["shared via a > shared | b > shared @ package.json:0"]
        );
    }
}
