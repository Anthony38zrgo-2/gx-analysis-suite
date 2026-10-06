//! `gx` — CLI productivo (GX-012/GX-013/GX-014).
//!
//! Códigos de salida documentados:
//! - `0` — escaneo OK y quality gate PASS (incluye cero hallazgos).
//! - `1` — quality gate REJECT (fuera de la política).
//! - `2` — invocación inválida (clap o falta de path).
//! - `3` — fallo de scan/infraestructura (archivo corrupto, no soportado,
//!   inexistente, fallo de base de datos).

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use gx_core::models::{AnalysisRequest, AnalysisResult, QgPolicy, QgVerdict};
use gx_storage::dao::rules_dao;

const EXIT_PASS: i32 = 0;
const EXIT_REJECT: i32 = 1;
const EXIT_INVALID: i32 = 2;
const EXIT_SCAN_FAILURE: i32 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "gx",
    version,
    about = "GeneXus Static Analysis Linter CLI",
    after_help = "Códigos de salida: 0 pass · 1 reject · 2 invocación inválida · 3 fallo de scan"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Escanea un archivo o directorio GeneXus y evalúa el quality gate.
    Scan {
        /// Ruta fuente GeneXus (.txt/.xml/.xpz o directorio; recursivo).
        path: Option<String>,
        /// Compatibilidad con el CLI anterior: --file <ruta>.
        #[arg(long, value_name = "PATH")]
        file: Option<String>,
        /// Formato de salida: text | json | ndjson (un finding por línea y
        /// una línea final de resumen).
        #[arg(long, default_value = "text", value_name = "FMT")]
        format: String,
        /// Política absolute: máximo de errores permitidos.
        #[arg(long, default_value_t = 0)]
        max_errors: u32,
        /// Política absolute: máximo de warnings permitidos.
        #[arg(long, default_value_t = 999_999)]
        max_warnings: u32,
        /// Política percentage (GUI legada): % máximo de errores.
        #[arg(long, value_name = "PCT")]
        error_pct: Option<f32>,
        /// Reglas a habilitar (lista separada por comas; domina al resto).
        #[arg(long, value_delimiter = ',', value_name = "IDS")]
        enable: Vec<String>,
        /// Reglas a deshabilitar sobre el set por defecto.
        #[arg(long, value_delimiter = ',', value_name = "IDS")]
        disable: Vec<String>,
        /// Perfil de reglas sin --enable: `default` (catálogo del producto) o
        /// `local` (estado toggled en la base local del usuario).
        #[arg(long, value_name = "PERFIL", default_value = "default")]
        rules_profile: String,
        /// Carga el catálogo desde Reglas.csv (en memoria, sin base local).
        #[arg(long, value_name = "CSV")]
        rules_csv: Option<String>,
        /// Persiste el historial de auditoría en la base local.
        #[arg(long)]
        record_history: bool,
        /// Base de datos local alternativa (para pruebas/uso avanzado).
        #[arg(long, value_name = "DB")]
        db: Option<String>,
        /// Genera además un PDF del resultado (su fallo NO altera el exit code).
        #[arg(long, value_name = "PDF")]
        pdf: Option<String>,
    },
    /// Gestión del catálogo de reglas.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Genera un PDF desde un AnalysisResult serializado (GX-019).
    ExportPdf {
        /// JSON con el AnalysisResult (salida de `gx scan --format json`).
        #[arg(long, value_name = "JSON")]
        result_file: String,
        /// Ruta del PDF de salida.
        #[arg(long, value_name = "PDF")]
        out: String,
    },
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    /// Lista el catálogo de reglas (id, estado, severidad, triggers).
    List {
        /// Formato: text | json.
        #[arg(long, default_value = "text")]
        format: String,
        /// Catálogo desde Reglas.csv en memoria (sin base local).
        #[arg(long, value_name = "CSV")]
        rules_csv: Option<String>,
        /// Base de datos local alternativa.
        #[arg(long, value_name = "DB")]
        db: Option<String>,
    },
    /// Habilita una regla en la base local.
    Enable {
        /// Id de regla, ej: GX.2.6.
        id: String,
        #[arg(long, value_name = "DB")]
        db: Option<String>,
    },
    /// Deshabilita una regla en la base local.
    Disable {
        /// Id de regla, ej: GX.2.6.
        id: String,
        #[arg(long, value_name = "DB")]
        db: Option<String>,
    },
}

fn main() -> ExitCode {
    // Avisos del engine (p. ej. objetos sin código) a stderr; stdout queda
    // limpio para el documento JSON (GX-013).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("[gx] error: {e:#}");
            ExitCode::from(EXIT_SCAN_FAILURE as u8)
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Scan {
            path,
            file,
            format,
            max_errors,
            max_warnings,
            error_pct,
            enable,
            disable,
            rules_profile,
            rules_csv,
            record_history,
            db,
            pdf,
        } => cmd_scan(
            path,
            file,
            &format,
            max_errors,
            max_warnings,
            error_pct,
            &enable,
            &disable,
            &rules_profile,
            rules_csv.as_deref(),
            record_history,
            db.as_deref(),
            pdf.as_deref(),
        ),
        Commands::Rules { action } => cmd_rules(action),
        Commands::ExportPdf { result_file, out } => cmd_export_pdf(&result_file, &out),
    }
}

fn open_db(db_flag: Option<&str>) -> Result<rusqlite::Connection> {
    let res = match db_flag {
        Some(p) => gx_storage::db::init_db_at(std::path::Path::new(p)),
        None => gx_storage::db::init_db(),
    };
    res.map_err(|e| anyhow::anyhow!("base de datos: {e}"))
}

/// Set de reglas efectivo: perfil (default/local/CSV) + overrides de CLI.
///
/// `--enable` actúa como whitelist (habilita SÓLO las reglas listadas);
/// `--disable` quita del set resultante. A01: los perfiles son explícitos;
/// el CLI ya no ignora en silencio el estado local de reglas.
fn effective_rules(
    rules_csv: Option<&str>,
    profile: &str,
    db: Option<&str>,
    enable: &[String],
    disable: &[String],
) -> Result<Vec<String>> {
    let mut ids: HashSet<String> = if !enable.is_empty() {
        enable.iter().map(|s| s.trim().to_string()).collect()
    } else {
        match rules_csv {
            Some(csv) => {
                let conn = gx_storage::db::init_memory_db()?;
                gx_storage::seed::import_reglas_csv(&conn, std::path::Path::new(csv))?;
                rules_dao::get_enabled_ids(&conn)?.into_iter().collect()
            }
            None => match profile {
                "default" => gx_storage::seed::default_enabled_ids(),
                "local" => {
                    let conn = open_db(db)?;
                    rules_dao::get_enabled_ids(&conn)?.into_iter().collect()
                }
                other => {
                    anyhow::bail!("perfil de reglas inválido '{other}' (esperado default|local)")
                }
            },
        }
    };
    for id in disable {
        ids.remove(id.trim());
    }
    let mut out: Vec<String> = ids.into_iter().collect();
    out.sort();
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn cmd_scan(
    path: Option<String>,
    file: Option<String>,
    format: &str,
    max_errors: u32,
    max_warnings: u32,
    error_pct: Option<f32>,
    enable: &[String],
    disable: &[String],
    profile: &str,
    rules_csv: Option<&str>,
    record_history: bool,
    db: Option<&str>,
    pdf: Option<&str>,
) -> Result<i32> {
    // Invocación inválida: sin path (código 2).
    let Some(path_str) = path.or(file) else {
        eprintln!("[gx] falta la ruta: `gx scan <ruta>` o `gx scan --file <ruta>`");
        return Ok(EXIT_INVALID);
    };
    if !matches!(format, "text" | "json" | "ndjson") {
        eprintln!("[gx] formato inválido '{format}' (esperado text|json|ndjson)");
        return Ok(EXIT_INVALID);
    }
    let path = PathBuf::from(path_str);

    // A01: un --disable de una regla inexistente es un error de invocación,
    // no un no-op silencioso.
    for id in disable {
        let id = id.trim();
        if !gx_engine::runtime::is_known_rule(id) {
            eprintln!("[gx] regla desconocida en --disable: '{id}'");
            return Ok(EXIT_INVALID);
        }
    }

    let policy = match error_pct {
        Some(pct) => QgPolicy::Percentage { max_error_pct: pct },
        None => QgPolicy::Absolute {
            max_errors,
            max_warnings,
        },
    };

    let request = AnalysisRequest {
        schema_version: 1,
        inputs: vec![path.clone()],
        enabled_rule_ids: effective_rules(rules_csv, profile, db, enable, disable)?,
        policy,
        record_history,
    };

    // A01/F01: la validación compartida rechaza esquema, reglas y política
    // inválidos ANTES de escanear; nunca exit 0/PASS con un request inválido.
    if let Err(e) = gx_engine::runtime::validate_request(&request) {
        eprintln!("[gx] solicitud inválida: {e}");
        return Ok(EXIT_INVALID);
    }

    let result = gx_engine::runtime::analyze(&request);

    // Historial opt-in (GX-011/GX-013: CI no escribe).
    if record_history {
        let run = gx_storage::dao::audit_dao::AuditRun::from_analysis(&request, &result, "cli");
        let mut conn = open_db(db)?;
        gx_storage::dao::audit_dao::persist_run(&mut conn, &run, &result.findings)?;
    }

    // GX-019: PDF opcional; un fallo del PDF NUNCA altera el veredicto.
    if let Some(pdf_path) = pdf {
        if let Err(e) = gx_report::render(&result, std::path::Path::new(pdf_path)) {
            eprintln!("[gx] aviso: no se pudo generar el PDF '{pdf_path}': {e:#}");
        }
    }

    // Fallos de scan SIEMPRE a stderr, en ambos formatos (GX-013).
    for f in &result.failures {
        eprintln!("[gx] FALLO {}: {}", f.path.display(), f.error);
    }

    match format {
        "json" => {
            // STDOUT = un documento JSON completo; progreso/errores a stderr.
            // C01: el framing de `json` NO cambia.
            serde_json::to_writer_pretty(std::io::stdout().lock(), &result)?;
            println!();
        }
        "ndjson" => {
            // C01: streaming separado y documentado; un finding por línea y
            // una línea final de resumen con el veredicto y la cobertura.
            use std::io::Write;
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            for issue in &result.findings {
                serde_json::to_writer(&mut lock, issue)?;
                lock.write_all(b"\n")?;
            }
            let summary = serde_json::json!({
                "type": "summary",
                "schema_version": result.schema_version,
                "scanned_files": result.scanned_files,
                "metrics": result.metrics,
                "verdict": result.verdict,
                "failures": result.failures,
                "coverage": result.coverage,
                "completion": result.completion,
                "findings_total": result.findings.len(),
            });
            serde_json::to_writer(&mut lock, &summary)?;
            lock.write_all(b"\n")?;
        }
        _ => print!("{}", gx_core::summary::text_summary(&result)),
    }

    match result.verdict {
        QgVerdict::Pass => Ok(EXIT_PASS),
        QgVerdict::Reject => Ok(EXIT_REJECT),
        QgVerdict::Error => Ok(EXIT_SCAN_FAILURE),
    }
}

fn cmd_rules(action: RulesAction) -> Result<i32> {
    match action {
        RulesAction::List {
            format,
            rules_csv,
            db,
        } => {
            let records: Vec<gx_storage::dao::rules_dao::RuleRecord> =
                if let Some(csv) = rules_csv.as_deref() {
                    let conn = gx_storage::db::init_memory_db()?;
                    gx_storage::seed::import_reglas_csv(&conn, std::path::Path::new(csv))?;
                    rules_dao::get_all(&conn)?
                } else {
                    let conn = open_db(db.as_deref())?;
                    rules_dao::get_all(&conn)?
                };
            if format == "json" {
                serde_json::to_writer_pretty(std::io::stdout().lock(), &records)?;
                println!();
            } else {
                for r in records.iter().filter(|r| !r.is_abstract) {
                    println!(
                        "{:<10} {:<8} {:<9} {:<30} {}",
                        r.id,
                        if r.enabled { "ON" } else { "OFF" },
                        r.severity,
                        r.triggers,
                        r.name
                    );
                }
                let concrete = records.iter().filter(|r| !r.is_abstract).count();
                println!(
                    "[gx] {concrete} reglas operativas (de {} en catálogo)",
                    records.len()
                );
            }
            Ok(EXIT_PASS)
        }
        RulesAction::Enable { id, db } => {
            let conn = open_db(db.as_deref())?;
            rules_dao::set_enabled(&conn, &id, true)?;
            println!("[gx] {id} habilitada");
            Ok(EXIT_PASS)
        }
        RulesAction::Disable { id, db } => {
            let conn = open_db(db.as_deref())?;
            rules_dao::set_enabled(&conn, &id, false)?;
            println!("[gx] {id} deshabilitada");
            Ok(EXIT_PASS)
        }
    }
}

/// GX-019: genera un PDF desde un `AnalysisResult` serializado, sin
/// re-ejecutar el engine.
fn cmd_export_pdf(result_file: &str, out: &str) -> Result<i32> {
    let json = std::fs::read_to_string(result_file)
        .map_err(|e| anyhow::anyhow!("no se pudo leer '{result_file}': {e}"))?;
    let result: AnalysisResult = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("'{result_file}' no es un AnalysisResult válido: {e}"))?;
    gx_report::render(&result, std::path::Path::new(out))?;
    println!(
        "[gx] PDF generado: {out} ({} hallazgos)",
        result.metrics.total_findings
    );
    Ok(EXIT_PASS)
}
