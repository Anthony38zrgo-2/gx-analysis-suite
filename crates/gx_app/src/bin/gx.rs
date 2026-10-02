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

use gx_core::models::{AnalysisRequest, QgPolicy, QgVerdict};
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
        /// Formato de salida: text | json (stdout = un documento JSON).
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
        /// Carga el catálogo desde Reglas.csv (en memoria, sin base local).
        #[arg(long, value_name = "CSV")]
        rules_csv: Option<String>,
        /// Persiste el historial de auditoría en la base local.
        #[arg(long)]
        record_history: bool,
        /// Base de datos local alternativa (para pruebas/uso avanzado).
        #[arg(long, value_name = "DB")]
        db: Option<String>,
    },
    /// Gestión del catálogo de reglas.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
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
            rules_csv,
            record_history,
            db,
        } => cmd_scan(
            path,
            file,
            &format,
            max_errors,
            max_warnings,
            error_pct,
            &enable,
            &disable,
            rules_csv.as_deref(),
            record_history,
            db.as_deref(),
        ),
        Commands::Rules { action } => cmd_rules(action),
    }
}

fn open_db(db_flag: Option<&str>) -> Result<rusqlite::Connection> {
    let res = match db_flag {
        Some(p) => gx_storage::db::init_db_at(std::path::Path::new(p)),
        None => gx_storage::db::init_db(),
    };
    res.map_err(|e| anyhow::anyhow!("base de datos: {e}"))
}

/// Set de reglas efectivo: base por defecto (o CSV), + overrides de CLI.
///
/// `--enable` actúa como whitelist (habilita SÓLO las reglas listadas);
/// `--disable` quita del set resultante.
fn effective_rules(
    rules_csv: Option<&str>,
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
            None => gx_storage::seed::default_enabled_ids(),
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
    rules_csv: Option<&str>,
    record_history: bool,
    db: Option<&str>,
) -> Result<i32> {
    // Invocación inválida: sin path (código 2).
    let Some(path_str) = path.or(file) else {
        eprintln!("[gx] falta la ruta: `gx scan <ruta>` o `gx scan --file <ruta>`");
        return Ok(EXIT_INVALID);
    };
    if !matches!(format, "text" | "json") {
        eprintln!("[gx] formato inválido '{format}' (esperado text|json)");
        return Ok(EXIT_INVALID);
    }
    let path = PathBuf::from(path_str);

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
        enabled_rule_ids: effective_rules(rules_csv, enable, disable)?,
        policy,
        record_history,
    };

    let result = gx_engine::runtime::analyze(&request);

    // Historial opt-in (GX-011/GX-013: CI no escribe).
    if record_history {
        let run = gx_storage::dao::audit_dao::AuditRun {
            file_path: path.to_string_lossy().to_string(),
            file_name: path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
            file_hash: None,
            file_size_bytes: std::fs::metadata(&path).ok().map(|m| m.len() as i64),
            triggered_by: "cli".to_string(),
            total_findings: result.metrics.total_findings as i64,
            errors: result.metrics.errors as i64,
            warnings: result.metrics.warnings as i64,
            info: result.metrics.info as i64,
            qg_passed: result.verdict == QgVerdict::Pass,
            qg_threshold_pct: match &request.policy {
                QgPolicy::Percentage { max_error_pct } => *max_error_pct,
                _ => 0.0,
            },
            duration_ms: None,
            pdf_path: None,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            policy: Some(request.policy.name().to_string()),
            verdict: Some(
                serde_json::to_string(&result.verdict)?
                    .trim_matches('"')
                    .to_string(),
            ),
            failures_json: if result.failures.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&result.failures)?)
            },
        };
        let mut conn = open_db(db)?;
        gx_storage::dao::audit_dao::persist_run(&mut conn, &run, &result.findings)?;
    }

    // Fallos de scan SIEMPRE a stderr, en ambos formatos (GX-013).
    for f in &result.failures {
        eprintln!("[gx] FALLO {}: {}", f.path.display(), f.error);
    }

    match format {
        "json" => {
            // STDOUT = un documento JSON completo; progreso/errores a stderr.
            serde_json::to_writer_pretty(std::io::stdout().lock(), &result)?;
            println!();
        }
        _ => print_text_summary(&result)?,
    }

    match result.verdict {
        QgVerdict::Pass => Ok(EXIT_PASS),
        QgVerdict::Reject => Ok(EXIT_REJECT),
        QgVerdict::Error => Ok(EXIT_SCAN_FAILURE),
    }
}

fn print_text_summary(result: &gx_core::models::AnalysisResult) -> Result<()> {
    println!(
        "[gx] política: {}",
        match &result.policy {
            QgPolicy::Absolute {
                max_errors,
                max_warnings,
            } => format!("absolute (max_errors={max_errors}, max_warnings={max_warnings})"),
            QgPolicy::Percentage { max_error_pct } =>
                format!("percentage (max_error_pct={max_error_pct})"),
        }
    );
    println!(
        "[gx] archivos escaneados: {} | hallazgos: {} ({} ERROR / {} WARNING / {} INFO)",
        result.scanned_files,
        result.metrics.total_findings,
        result.metrics.errors,
        result.metrics.warnings,
        result.metrics.info
    );
    for issue in &result.findings {
        let object = match &issue.object {
            Some(o) => format!(" [{} ({}) {}]", o.id, o.object_type, o.member),
            None => String::new(),
        };
        println!(
            "{:<7} {:<10} línea {:<4}{} {}",
            issue.severity.as_str(),
            issue.rule_id,
            issue.line_number,
            object,
            issue.description
        );
    }
    let verdict = match result.verdict {
        QgVerdict::Pass => "PASS",
        QgVerdict::Reject => "REJECT",
        QgVerdict::Error => "ERROR (fallos de scan)",
    };
    println!("[gx] quality gate: {verdict} ({})", result.policy.name());
    Ok(())
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
