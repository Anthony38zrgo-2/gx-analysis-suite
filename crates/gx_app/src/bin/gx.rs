use clap::Parser;

/// GeneXus Static Analysis Linter CLI
#[derive(Parser, Debug)]
#[command(name = "gx", version, about = "GeneXus Static Analysis Linter CLI")]
struct Cli {
    /// Ruta archivo fuente GeneXus
    #[arg(long, required = true, value_name = "PATH")]
    file: String,
    /// Umbral máximo errores (Quality Gate CLI)
    #[arg(long, default_value_t = 0)]
    max_errors: u32,
    /// Umbral máximo warnings (Quality Gate CLI)
    #[arg(long, default_value_t = 999_999)]
    max_warnings: u32,
}

fn main() {
    let _cli = Cli::parse();
    println!("gx CLI scaffold — implementación en EPIC-08");
}
