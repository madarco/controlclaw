//! The conformance runner (docs/plans/rust-rewrite.md §4.2): the same HTTP-level cases against the
//! TS build and the Rust build of an agent, so parity is measured. A case is only valid if it
//! passes on TS; one that passes on TS and fails on Rust is a bug in the Rust build.
//!
//! `--target saas|local|cp` runs the control-plane cases instead (`cp.rs`): the same contract checked
//! from the other side, against the SaaS routes and the standalone firewall's local control plane.
//!
//! Called as `systemctl`, `sudo` or `journalctl` (the runner links them to itself) it is the
//! recording stand-in for those helpers instead.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};

mod case;
mod cp;
mod fake_agent;
mod matcher;
mod runner;
mod shim;

use runner::{Builds, Target};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Which {
    Ts,
    Rust,
    Both,
    /// The control-plane cases against the SaaS routes.
    Saas,
    /// The control-plane cases against the local control plane.
    Local,
    /// The control-plane cases against both.
    Cp,
}

#[derive(Parser)]
#[command(about = "Run the conformance cases against the TS and the Rust agents")]
struct Args {
    /// Case files or folders (searched for *.yaml).
    #[arg(default_value = "conformance/cases")]
    cases: Vec<PathBuf>,
    #[arg(long, value_enum, default_value = "both")]
    target: Which,
    /// Only cases whose name contains this.
    #[arg(long)]
    filter: Option<String>,
    /// The repository root (where packages/ is). Found from the current folder when not given.
    #[arg(long, env = "CC_REPO")]
    repo: Option<PathBuf>,
    /// Where the Rust binaries are.
    #[arg(long, env = "CC_RUST_BIN_DIR")]
    rust_bin_dir: Option<PathBuf>,
    #[arg(long, env = "CC_NODE", default_value = "node")]
    node: String,
}

fn find_repo() -> Option<PathBuf> {
    let mut d = std::env::current_dir().ok()?;
    loop {
        if d.join("pnpm-workspace.yaml").exists() {
            return Some(d);
        }
        if !d.pop() {
            return None;
        }
    }
}

fn collect(paths: &[PathBuf], out: &mut Vec<PathBuf>) -> Result<()> {
    for p in paths {
        if p.is_dir() {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(p)?.filter_map(|e| e.ok().map(|e| e.path())).collect();
            entries.sort();
            collect(&entries, out)?;
        } else if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(p.clone());
        }
    }
    Ok(())
}

fn load(path: &Path) -> Result<case::Case> {
    let raw = std::fs::read_to_string(path)?;
    let mut c: case::Case = serde_yaml::from_str(&raw).with_context(|| format!("{}", path.display()))?;
    c.dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    Ok(c)
}

#[tokio::main]
async fn main() -> Result<()> {
    let argv0 = std::env::args().next().unwrap_or_default();
    let program = Path::new(&argv0)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if shim::PROGRAMS.contains(&program.as_str()) {
        shim::run(&program);
    }
    let args = Args::parse();
    let repo = args
        .repo
        .or_else(find_repo)
        .context("could not find the repository root; pass --repo")?;
    let rust_bin_dir = args.rust_bin_dir.unwrap_or_else(|| repo.join("rust/target/debug"));
    let builds = Builds {
        repo,
        rust_bin_dir,
        node: args.node,
    };
    let mut files = Vec::new();
    collect(&args.cases, &mut files)?;
    let (cp_files, files) = cp::files(&files);
    let targets: Vec<Target> = match args.target {
        Which::Ts => vec![Target::Ts],
        Which::Rust => vec![Target::Rust],
        Which::Both => vec![Target::Ts, Target::Rust],
        Which::Saas => {
            return run_cp(
                &cp_files,
                &[cp::CpTarget::Saas],
                &args.filter,
                &builds.repo,
                &builds.rust_bin_dir,
            )
            .await;
        }
        Which::Local => {
            return run_cp(
                &cp_files,
                &[cp::CpTarget::Local],
                &args.filter,
                &builds.repo,
                &builds.rust_bin_dir,
            )
            .await;
        }
        Which::Cp => {
            return run_cp(
                &cp_files,
                &[cp::CpTarget::Saas, cp::CpTarget::Local],
                &args.filter,
                &builds.repo,
                &builds.rust_bin_dir,
            )
            .await;
        }
    };
    let (mut passed, mut failed, mut skipped) = (0, 0, 0);
    println!("{:<60} {:<12} {:<12}", "case", "ts", "rust");
    for f in files {
        let c = load(&f)?;
        if args.filter.as_ref().is_some_and(|x| !c.name.contains(x.as_str())) {
            continue;
        }
        let mut cols = Vec::new();
        let mut errors = Vec::new();
        for t in [Target::Ts, Target::Rust] {
            if !targets.contains(&t) {
                cols.push("-".to_string());
                continue;
            }
            if let Some(why) = c.skip.get(t.name()) {
                skipped += 1;
                cols.push(format!("skip ({why})"));
                continue;
            }
            match runner::run(&c, t, &builds).await {
                Ok(runner::Outcome::Pass) => {
                    passed += 1;
                    cols.push("pass".into());
                }
                Ok(runner::Outcome::Skip(why)) => {
                    skipped += 1;
                    cols.push(format!("skip ({why})"));
                }
                Err(e) => {
                    failed += 1;
                    cols.push("FAIL".into());
                    errors.push(format!("[{}] {}: {e:#}", t.name(), c.name));
                }
            }
        }
        println!("{:<60} {:<12} {:<12}", c.name, cols[0], cols[1]);
        for e in errors {
            eprintln!("{e}\n");
        }
    }
    println!("\n{passed} passed, {failed} failed, {skipped} skipped");
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// The control-plane cases, one column per target. The SaaS harness is started once for all of them.
async fn run_cp(
    files: &[PathBuf],
    targets: &[cp::CpTarget],
    filter: &Option<String>,
    repo: &Path,
    rust_bin_dir: &Path,
) -> Result<()> {
    let (mut passed, mut failed, mut skipped) = (0, 0, 0);
    let mut cases = Vec::new();
    for f in files {
        match cp::load(f) {
            Ok(c) if filter.as_ref().is_none_or(|x| c.name.contains(x.as_str())) => cases.push(c),
            Ok(_) => {}
            // One file that does not parse is that case's failure, not the run's.
            Err(e) => {
                failed += 1;
                eprintln!("{e:#}\n");
            }
        }
    }
    let saas = if targets.contains(&cp::CpTarget::Saas) && !cases.is_empty() {
        Some(cp::Server::start_saas(repo).await?)
    } else {
        None
    };
    let local = if targets.contains(&cp::CpTarget::Local) && !cases.is_empty() {
        Some(cp::Server::start_local(rust_bin_dir).await?)
    } else {
        None
    };
    println!("{:<60} {:<12} {:<12}", "case", "saas", "local");
    for c in &cases {
        let mut cols = Vec::new();
        let mut errors = Vec::new();
        for t in [cp::CpTarget::Saas, cp::CpTarget::Local] {
            if !targets.contains(&t) {
                cols.push("-".to_string());
                continue;
            }
            let server = match t {
                cp::CpTarget::Saas => saas.as_ref(),
                cp::CpTarget::Local => local.as_ref(),
            };
            match cp::run(c, t, server).await {
                Ok(cp::Outcome::Pass) => {
                    passed += 1;
                    cols.push("pass".into());
                }
                Ok(cp::Outcome::Skip(why)) => {
                    skipped += 1;
                    cols.push(format!("skip ({why})"));
                }
                Err(e) => {
                    failed += 1;
                    cols.push("FAIL".into());
                    errors.push(format!("[{}] {} ({}): {e:#}", t.name(), c.name, c.endpoint));
                }
            }
        }
        println!("{:<60} {:<12} {:<12}", c.name, cols[0], cols[1]);
        for e in errors {
            eprintln!("{e}\n");
        }
    }
    for s in [saas, local].into_iter().flatten() {
        s.stop();
    }
    println!("\n{passed} passed, {failed} failed, {skipped} skipped");
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}
