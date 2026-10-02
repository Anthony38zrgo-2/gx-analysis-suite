//! xtask — helpers de build/release del workspace (GX-020).

use std::path::Path;
use std::process::Command;

fn main() -> anyhow::Result<()> {
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "help".to_string());
    match command.as_str() {
        "build" => build(true),
        "build-debug" => build(false),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("[xtask] comando desconocido: '{other}'");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!("xtask — helpers del workspace gx-linter-rs");
    println!("  cargo xtask build        release build + copia a dist/gx.exe");
    println!("  cargo xtask build-debug  debug build + copia a dist/gx.exe");
}

fn build(release: bool) -> anyhow::Result<()> {
    let profile = if release { "release" } else { "debug" };
    println!("[xtask] cargo build --workspace --{profile}");

    let mut args = vec!["build", "--workspace"];
    if release {
        args.push("--release");
    }
    let status = Command::new("cargo").args(&args).status()?;
    if !status.success() {
        anyhow::bail!("cargo build falló ({status})");
    }

    let source = Path::new("target").join(profile).join("gx.exe");
    if source.is_file() {
        std::fs::create_dir_all("dist")?;
        let destination = Path::new("dist").join("gx.exe");
        std::fs::copy(&source, &destination)?;
        println!(
            "[xtask] copiado {} -> {}",
            source.display(),
            destination.display()
        );
    }
    Ok(())
}
