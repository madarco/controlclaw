//! Format changes, for when a store's format must change after the port (the port itself changes
//! none: plan §5.2). Each step is versioned and runs once per box, in id order, recorded in a
//! ledger. Before a step rewrites a file, the file is copied to `<file>.pre-<id>`; `down` puts
//! those copies back (or runs the step's own way back), so a box can return to the build before.
//! The copies stay until `cleanup`, which Ansible runs once the new build has started cleanly.
//!
//! A step is added here by W0 when a workstream asks; it never edits a file it did not list.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::store::Role;

/// What a step may use: the box paths, and the box key and ids an encrypted store is sealed with.
#[allow(dead_code)] // the key and ids are for the first step that rewrites an encrypted store
pub struct StepCtx<'a> {
    pub root: &'a Path,
    pub box_key: Option<&'a str>,
    pub org_id: &'a str,
    pub box_id: &'a str,
}

impl StepCtx<'_> {
    /// A box path under the root.
    pub fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    /// Write a listed file the way a step should:
    #[allow(dead_code)] // for the first step atomically, never through a symlink, and with
    /// the owner and mode the file had (cc-migrate runs as root; a file it wrote as root:root would
    /// lock its service out). A file that is new takes its folder's owner and mode 0600.
    pub fn write(&self, box_path: &str, data: &[u8]) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let p = self.path(box_path);
        let (mode, owner) = match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => return Err(format!("{} is a symlink", p.display())),
            Ok(m) => (m.mode() & 0o777, (m.uid(), m.gid())),
            Err(_) => {
                let dir = p.parent().and_then(|d| std::fs::metadata(d).ok());
                (0o600, dir.map(|m| (m.uid(), m.gid())).unwrap_or((0, 0)))
            }
        };
        cc_store::write_atomic_owned(&p, data, mode, cc_store::TmpName::Suffix, Some(owner))
            .map_err(|e| format!("write {}: {e}", p.display()))
    }
}

type StepFn = fn(&StepCtx) -> Result<(), String>;

pub struct Step {
    /// `0001-short-name`; steps run in this order.
    pub id: &'static str,
    pub role: Role,
    /// Every file the step may rewrite, as box paths. Each is copied before it runs.
    pub files: &'static [&'static str],
    pub up: StepFn,
    /// The step's own way back; `None` puts the `.pre-<id>` copies back. It must be safe to run
    /// twice: after `cleanup` there are no copies, and one cut short runs again.
    pub down: Option<StepFn>,
}

/// None yet: the port keeps every format.
pub const STEPS: &[Step] = &[];

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Ledger {
    pub applied: Vec<Applied>,
    /// Fields a later build may add; kept.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Copies made, the step started and did not finish (a crash, or a failure being undone).
    Running,
    Done,
    /// The step's own way back started and did not finish: the copies put it back.
    Undoing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Applied {
    pub id: String,
    pub role: Role,
    pub state: State,
    pub at: String,
    /// The listed files that existed before the step, so undoing it removes the ones it made.
    pub existed: Vec<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Ledger {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        cc_store::write_json_atomic(path, self, 0o600, cc_store::TmpName::Suffix).map_err(|e| e.to_string())
    }

    pub fn entry(&self, id: &str) -> Option<&Applied> {
        self.applied.iter().find(|a| a.id == id)
    }

    /// The step finished here.
    pub fn done(&self, id: &str) -> bool {
        self.entry(id).is_some_and(|a| a.state == State::Done)
    }

    fn remove(&mut self, id: &str) {
        self.applied.retain(|a| a.id != id);
    }
}

fn pre(path: &Path, id: &str) -> PathBuf {
    PathBuf::from(format!("{}.pre-{id}", path.display()))
}

/// One run at a time: an exclusive lock on `<ledger>.lock`, held until the returned file drops. A
/// second run fails at once rather than waiting or interleaving.
pub fn lock(ledger: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = ledger.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let path = PathBuf::from(format!("{}.lock", ledger.display()));
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(0o400_000) // O_NOFOLLOW
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err("another cc-migrate is running on this box".into()),
        Err(std::fs::TryLockError::Error(e)) => Err(format!("{}: {e}", path.display())),
    }
}

/// A path that is a symlink is never read or copied: the folders belong to the service, and this
/// runs as root.
fn not_a_symlink(p: &Path) -> Result<std::fs::Metadata, String> {
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if m.file_type().is_symlink() {
        return Err(format!("{} is a symlink; refused", p.display()));
    }
    Ok(m)
}

/// Copy whole or not at all, with the source's mode, owner and group: cc-migrate runs as root,
/// and a store put back as root's would lock its own agent out of it.
fn copy_atomic(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = not_a_symlink(from)?;
    let data = std::fs::read(from).map_err(|e| format!("read {}: {e}", from.display()))?;
    // The owner is set before the rename (write_atomic_owned): a copy never exists as root's.
    cc_store::write_atomic_owned(
        to,
        &data,
        meta.permissions().mode() & 0o777,
        cc_store::TmpName::Suffix,
        Some((meta.uid(), meta.gid())),
    )
    .map_err(|e| format!("copy to {}: {e}", to.display()))
}

/// What a step wrote, made durable before the ledger says so: every listed file that is there,
/// and its folder. Without it a power loss could keep the ledger and lose the files.
fn sync_listed(s: &Step, ctx: &StepCtx) -> Result<(), String> {
    for f in s.files {
        let p = ctx.path(f);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => return Err(format!("{} is a symlink; refused", p.display())),
            Ok(_) => std::fs::File::open(&p)
                .and_then(|h| h.sync_all())
                .map_err(|e| format!("sync {}: {e}", p.display()))?,
            Err(_) => {}
        }
        cc_store::sync_dir(&p).map_err(|e| format!("sync the folder of {}: {e}", p.display()))?;
    }
    Ok(())
}

/// After `up`: each listed file that had a copy gets back the copy's owner and mode, in case the
/// step wrote it without [`StepCtx::write`].
fn keep_owners(s: &Step, ctx: &StepCtx) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for f in s.files {
        let p = ctx.path(f);
        let Ok(c) = not_a_symlink(&pre(&p, s.id)) else { continue };
        let Ok(m) = std::fs::symlink_metadata(&p) else { continue };
        if m.file_type().is_symlink() {
            return Err(format!("{} is a symlink; refused", p.display()));
        }
        if (m.uid(), m.gid()) != (c.uid(), c.gid()) {
            std::os::unix::fs::lchown(&p, Some(c.uid()), Some(c.gid()))
                .map_err(|e| format!("owner of {}: {e}", p.display()))?;
        }
        if m.mode() & 0o777 != c.mode() & 0o777 {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(c.mode() & 0o777))
                .map_err(|e| format!("mode of {}: {e}", p.display()))?;
        }
    }
    Ok(())
}

/// Put the listed files back as they were before step `id`: the copies copied back (kept, so this
/// can run again after a crash; they go once the ledger says the step is undone), files the step
/// made removed. Every failure is reported, not only the first.
fn restore(s: &Step, ctx: &StepCtx, existed: &[String]) -> Result<(), String> {
    let mut errors = Vec::new();
    for f in s.files {
        let p = ctx.path(f);
        let c = pre(&p, s.id);
        if existed.iter().any(|e| e == f) {
            if !c.exists() {
                errors.push(format!("{} is gone, so the way back is too", c.display()));
            } else if let Err(e) = copy_atomic(&c, &p) {
                errors.push(format!("put back {}: {e}", p.display()));
            }
        } else if p.exists()
            && let Err(e) = std::fs::remove_file(&p).and_then(|()| cc_store::sync_dir(&p))
        {
            errors.push(format!("remove {} (made by the step): {e}", p.display()));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Entries of `role` this build has no step for: a newer build applied them.
fn unknown(steps: &[Step], role: Role, ledger: &Ledger) -> Option<String> {
    ledger
        .applied
        .iter()
        .find(|a| a.role == role && !steps.iter().any(|s| s.id == a.id))
        .map(|a| a.id.clone())
}

fn remove_copies(s: &Step, ctx: &StepCtx) -> Result<usize, String> {
    let mut n = 0;
    for f in s.files {
        let c = pre(&ctx.path(f), s.id);
        if c.exists() {
            std::fs::remove_file(&c).map_err(|e| format!("remove {}: {e}", c.display()))?;
            n += 1;
        }
    }
    Ok(n)
}

/// Run every step of `role` not done here, in order. A step left running by a crash is first put
/// back from its copies, then run again from the start. Stops at the first failure, with that
/// step's files put back. Returns the ids applied.
pub fn up(steps: &[Step], role: Role, ctx: &StepCtx, ledger_path: &Path) -> Result<Vec<String>, String> {
    let mut ledger = Ledger::load(ledger_path)?;
    if let Some(id) = unknown(steps, role, &ledger) {
        return Err(format!(
            "{id} was applied by a newer build: undo it with that build's cc-migrate down first"
        ));
    }
    let mut done = Vec::new();
    let mut todo: Vec<&Step> = steps.iter().filter(|s| s.role == role && !ledger.done(s.id)).collect();
    todo.sort_by_key(|s| s.id);
    for s in todo {
        if let Some(e) = ledger.entry(s.id).cloned() {
            restore(s, ctx, &e.existed)
                .map_err(|err| format!("{}: left running, and could not be put back: {err}", s.id))?;
            ledger.remove(s.id);
            ledger.save(ledger_path)?;
        }
        // Fresh copies every time: one left from an undone run holds older contents.
        remove_copies(s, ctx).map_err(|e| format!("{}: {e}", s.id))?;
        let mut existed = Vec::new();
        for f in s.files {
            let p = ctx.path(f);
            if p.exists() {
                copy_atomic(&p, &pre(&p, s.id)).map_err(|e| format!("{}: {e}", s.id))?;
                existed.push((*f).to_string());
            }
        }
        // Recorded before the step touches anything, so a crash from here on is undone next time.
        ledger.applied.push(Applied {
            id: s.id.into(),
            role,
            state: State::Running,
            at: cc_crypto::store_health::iso_now(),
            existed: existed.clone(),
            extra: Default::default(),
        });
        ledger.save(ledger_path)?;
        if let Err(e) = (s.up)(ctx) {
            return match restore(s, ctx, &existed) {
                Ok(()) => {
                    ledger.remove(s.id);
                    ledger.save(ledger_path)?;
                    let _ = remove_copies(s, ctx);
                    Err(format!("{}: {e} (its files were put back)", s.id))
                }
                Err(r) => Err(format!("{}: {e}; and putting its files back failed: {r}", s.id)),
            };
        }
        keep_owners(s, ctx).map_err(|e| format!("{}: {e}", s.id))?;
        sync_listed(s, ctx).map_err(|e| format!("{}: {e}", s.id))?;
        if let Some(a) = ledger.applied.iter_mut().find(|a| a.id == s.id) {
            a.state = State::Done;
        }
        ledger.save(ledger_path)?;
        done.push(s.id.to_string());
    }
    Ok(done)
}

/// Undo the steps of `role` applied here, newest first, down to (not including) `to`, which must be
/// one of them. A step this build does not know (a newer build applied it) stops it: that build's
/// `cc-migrate down` must undo it first.
pub fn down(
    steps: &[Step],
    role: Role,
    ctx: &StepCtx,
    ledger_path: &Path,
    to: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut ledger = Ledger::load(ledger_path)?;
    let mut applied: Vec<Applied> = ledger.applied.iter().filter(|a| a.role == role).cloned().collect();
    applied.sort_by(|a, b| a.id.cmp(&b.id));
    if let Some(t) = to
        && !applied.iter().any(|a| a.id == t)
    {
        return Err(format!("{t} is not a step applied on this box"));
    }
    let mut undone = Vec::new();
    for a in applied.into_iter().rev() {
        if to == Some(a.id.as_str()) {
            break;
        }
        let Some(s) = steps.iter().find(|s| s.id == a.id) else {
            return Err(format!(
                "{} was applied by a newer build: undo it with that build's cc-migrate down first",
                a.id
            ));
        };
        let copies_left = a.existed.iter().all(|f| pre(&ctx.path(f), &a.id).exists());
        match (s.down, a.state) {
            // The step's own way back, recorded as started first: if it stops halfway, the next
            // run puts the copies back rather than running it again on what it already changed.
            (Some(f), State::Done) => {
                if let Some(e) = ledger.applied.iter_mut().find(|x| x.id == a.id) {
                    e.state = State::Undoing;
                }
                ledger.save(ledger_path)?;
                f(ctx).map_err(|e| format!("{}: {e}", a.id))?;
            }
            // Cut short after `cleanup` took the copies: the own way back runs again. That is why
            // a step's own `down` must be safe to run twice.
            (Some(f), State::Undoing) if !copies_left => f(ctx).map_err(|e| format!("{}: {e}", a.id))?,
            _ => restore(s, ctx, &a.existed).map_err(|e| format!("{}: {e}", a.id))?,
        }
        sync_listed(s, ctx).map_err(|e| format!("{}: {e}", a.id))?;
        ledger.remove(&a.id);
        ledger.save(ledger_path)?;
        // Only now: until the ledger says it is undone, the copies are the way back.
        remove_copies(s, ctx).map_err(|e| format!("{}: {e}", a.id))?;
        undone.push(a.id);
    }
    Ok(undone)
}

/// The new build started cleanly: drop the copies of the steps of `role` done here. Returns how many.
pub fn cleanup(steps: &[Step], role: Role, ctx: &StepCtx, ledger_path: &Path) -> Result<usize, String> {
    let ledger = Ledger::load(ledger_path)?;
    let mut n = 0;
    for s in steps.iter().filter(|s| s.role == role && ledger.done(s.id)) {
        n += remove_copies(s, ctx)?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upper(ctx: &StepCtx) -> Result<(), String> {
        let p = ctx.path("/state/a.json");
        let s = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
        std::fs::write(&p, s.to_uppercase()).map_err(|e| e.to_string())
    }

    fn breaks(ctx: &StepCtx) -> Result<(), String> {
        std::fs::write(ctx.path("/state/a.json"), "half").map_err(|e| e.to_string())?;
        Err("broke halfway".into())
    }

    const ONE: &[Step] = &[Step {
        id: "0001-upper",
        role: Role::Agent,
        files: &["/state/a.json"],
        up: upper,
        down: None,
    }];
    const BAD: &[Step] = &[
        Step {
            id: "0001-upper",
            role: Role::Agent,
            files: &["/state/a.json"],
            up: upper,
            down: None,
        },
        Step {
            id: "0002-breaks",
            role: Role::Agent,
            files: &["/state/a.json"],
            up: breaks,
            down: None,
        },
    ];

    fn setup() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().expect("dir");
        std::fs::create_dir_all(d.path().join("state")).expect("mkdir");
        std::fs::write(d.path().join("state/a.json"), "abc").expect("write");
        let ledger = d.path().join("state/cc-migrate.json");
        (d, ledger)
    }

    #[test]
    fn up_once_then_down_puts_it_back() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        assert_eq!(up(ONE, Role::Agent, &ctx, &ledger).expect("up"), ["0001-upper"]);
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "ABC"
        );
        assert!(
            up(ONE, Role::Agent, &ctx, &ledger).expect("again").is_empty(),
            "a step runs once"
        );
        assert!(up(ONE, Role::Firewall, &ctx, &ledger).expect("other role").is_empty());
        assert_eq!(
            down(ONE, Role::Agent, &ctx, &ledger, None).expect("down"),
            ["0001-upper"]
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "abc"
        );
        assert!(Ledger::load(&ledger).expect("ledger").applied.is_empty());
    }

    #[test]
    fn a_crash_mid_step_is_undone_before_it_runs_again() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        // What a crash leaves: the copy, a running entry, and a half-written file.
        std::fs::copy(
            d.path().join("state/a.json"),
            d.path().join("state/a.json.pre-0001-upper"),
        )
        .expect("copy");
        std::fs::write(d.path().join("state/a.json"), "ABC").expect("half");
        let l = Ledger {
            applied: vec![Applied {
                id: "0001-upper".into(),
                role: Role::Agent,
                state: State::Running,
                at: "t".into(),
                existed: vec!["/state/a.json".into()],
                extra: Default::default(),
            }],
            extra: Default::default(),
        };
        l.save(&ledger).expect("save");
        up(ONE, Role::Agent, &ctx, &ledger).expect("up");
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "ABC",
            "converted once, not twice"
        );
        assert!(Ledger::load(&ledger).expect("ledger").done("0001-upper"));
    }

    fn makes(ctx: &StepCtx) -> Result<(), String> {
        std::fs::write(ctx.path("/state/new.json"), "{}").map_err(|e| e.to_string())
    }

    #[test]
    fn a_file_a_step_made_goes_when_it_is_undone() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        let steps = [Step {
            id: "0001-makes",
            role: Role::Agent,
            files: &["/state/new.json"],
            up: makes,
            down: None,
        }];
        up(&steps, Role::Agent, &ctx, &ledger).expect("up");
        assert!(d.path().join("state/new.json").exists());
        down(&steps, Role::Agent, &ctx, &ledger, None).expect("down");
        assert!(!d.path().join("state/new.json").exists());
    }

    #[test]
    fn down_stops_at_a_step_it_does_not_know_and_at_a_wrong_to() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        up(BAD, Role::Agent, &ctx, &ledger).expect_err("second fails");
        assert!(
            down(ONE, Role::Agent, &ctx, &ledger, Some("0001"))
                .expect_err("short id")
                .contains("not a step applied")
        );
        let newer = [Step {
            id: "0000-other",
            role: Role::Agent,
            files: &[],
            up: upper,
            down: None,
        }];
        assert!(
            down(&newer, Role::Agent, &ctx, &ledger, None)
                .expect_err("unknown")
                .contains("newer build")
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "ABC",
            "nothing undone"
        );
    }

    #[test]
    fn a_failed_step_is_undone_and_stops_the_rest() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        let e = up(BAD, Role::Agent, &ctx, &ledger).expect_err("fails");
        assert!(
            e.starts_with("0002-breaks: broke halfway (its files were put back)"),
            "{e}"
        );
        // The first step stays applied; the second's file is as the first left it.
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "ABC"
        );
        assert_eq!(Ledger::load(&ledger).expect("ledger").applied.len(), 1);
    }

    #[test]
    fn cleanup_drops_the_copies_and_with_them_the_way_back() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        up(ONE, Role::Agent, &ctx, &ledger).expect("up");
        assert_eq!(cleanup(ONE, Role::Agent, &ctx, &ledger).expect("cleanup"), 1);
        let e = down(ONE, Role::Agent, &ctx, &ledger, None).expect_err("no copy");
        assert!(e.contains("is gone"), "{e}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "ABC",
            "nothing changed"
        );
    }

    fn back(ctx: &StepCtx) -> Result<(), String> {
        let p = ctx.path("/state/a.json");
        let s = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
        std::fs::write(&p, s.to_lowercase()).map_err(|e| e.to_string())
    }

    #[test]
    fn up_stops_at_a_step_only_a_newer_build_knows() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        fn nothing(_: &StepCtx) -> Result<(), String> {
            Ok(())
        }
        let newer = [Step {
            id: "0003-newer",
            role: Role::Agent,
            files: &[],
            up: nothing,
            down: None,
        }];
        up(&newer, Role::Agent, &ctx, &ledger).expect("newer build");
        let e = up(ONE, Role::Agent, &ctx, &ledger).expect_err("older build");
        assert!(e.contains("newer build"), "{e}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "abc",
            "0001 did not run"
        );
    }

    #[test]
    fn restore_can_run_twice() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        up(ONE, Role::Agent, &ctx, &ledger).expect("up");
        restore(&ONE[0], &ctx, &["/state/a.json".to_string()]).expect("first");
        restore(&ONE[0], &ctx, &["/state/a.json".to_string()]).expect("again, as after a crash");
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "abc"
        );
    }

    #[test]
    fn an_own_way_back_cut_short_is_put_back_from_the_copies() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        let steps = [Step {
            id: "0001-upper",
            role: Role::Agent,
            files: &["/state/a.json"],
            up: upper,
            down: Some(back),
        }];
        up(&steps, Role::Agent, &ctx, &ledger).expect("up");
        // What a crash inside `back` leaves: the entry undoing, the file half done.
        let mut l = Ledger::load(&ledger).expect("ledger");
        l.applied[0].state = State::Undoing;
        l.save(&ledger).expect("save");
        std::fs::write(d.path().join("state/a.json"), "aBC").expect("half");
        down(&steps, Role::Agent, &ctx, &ledger, None).expect("down");
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "abc"
        );
        assert!(
            !d.path().join("state/a.json.pre-0001-upper").exists(),
            "copies go once it is undone"
        );
    }

    #[test]
    fn a_symlinked_store_is_refused() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        std::fs::write(d.path().join("shadow"), "root:secret").expect("target");
        std::fs::remove_file(d.path().join("state/a.json")).expect("rm");
        std::os::unix::fs::symlink(d.path().join("shadow"), d.path().join("state/a.json")).expect("symlink");
        let e = up(ONE, Role::Agent, &ctx, &ledger).expect_err("refused");
        assert!(e.contains("symlink"), "{e}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("shadow")).expect("read"),
            "root:secret"
        );
    }

    fn rewrites_with_write(ctx: &StepCtx) -> Result<(), String> {
        ctx.write("/state/a.json", b"via ctx")
    }

    fn rewrites_wide(ctx: &StepCtx) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let p = ctx.path("/state/a.json");
        std::fs::write(&p, "wide").map_err(|e| e.to_string())?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())
    }

    #[test]
    fn a_rewritten_store_keeps_its_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for up_fn in [rewrites_with_write as StepFn, rewrites_wide] {
            let (d, ledger) = setup();
            let ctx = StepCtx {
                root: d.path(),
                box_key: None,
                org_id: "o",
                box_id: "b",
            };
            let p = d.path().join("state/a.json");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("mode");
            let steps = [Step {
                id: "0001-x",
                role: Role::Agent,
                files: &["/state/a.json"],
                up: up_fn,
                down: None,
            }];
            up(&steps, Role::Agent, &ctx, &ledger).expect("up");
            assert_eq!(std::fs::metadata(&p).expect("meta").mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn one_run_at_a_time() {
        let (_d, ledger) = setup();
        let held = lock(&ledger).expect("first");
        assert!(lock(&ledger).expect_err("second").contains("another cc-migrate"));
        drop(held);
        assert!(lock(&ledger).is_ok());
    }

    #[test]
    fn an_own_way_back_cut_short_after_cleanup_runs_again() {
        let (d, ledger) = setup();
        let ctx = StepCtx {
            root: d.path(),
            box_key: None,
            org_id: "o",
            box_id: "b",
        };
        let steps = [Step {
            id: "0001-upper",
            role: Role::Agent,
            files: &["/state/a.json"],
            up: upper,
            down: Some(back),
        }];
        up(&steps, Role::Agent, &ctx, &ledger).expect("up");
        cleanup(&steps, Role::Agent, &ctx, &ledger).expect("cleanup");
        let mut l = Ledger::load(&ledger).expect("ledger");
        l.applied[0].state = State::Undoing;
        l.save(&ledger).expect("save");
        down(&steps, Role::Agent, &ctx, &ledger, None).expect("down runs the way back again");
        assert_eq!(
            std::fs::read_to_string(d.path().join("state/a.json")).expect("read"),
            "abc"
        );
        assert!(Ledger::load(&ledger).expect("ledger").applied.is_empty());
    }
}
