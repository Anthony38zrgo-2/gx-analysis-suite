//! Taint local acotado (D03) sobre el modelo semántico (D02).
//!
//! Subconjunto DOCUMENTADO de APIs GeneXus modeladas como fuentes, sinks y
//! funciones neutras. Lo que no está modelado NO se asume seguro: el taint se
//! conserva (propagación conservadora), la traza lo marca como
//! `unsupported_call` y la cobertura reporta `unsupported_sanitizers`.
//!
//! Límites: `MAX_PASSES` iteraciones de punto fijo, `MAX_TRACE` pasos por
//! traza y `MAX_FINDINGS` hallazgos por objeto. Todo el análisis es
//! intra-objeto (no interprocedural).

use std::collections::{HashMap, HashSet};

use crate::models::TraceStep;
use crate::semantics::{
    AccessKind, ParamDirection, SemanticModel, StatementKind, Token, TokenKind,
};

/// Pasadas de punto fijo (cubre reasignaciones dentro de bucles acotados).
pub const MAX_PASSES: usize = 4;
/// Pasos máximos por traza.
pub const MAX_TRACE: usize = 8;
/// Hallazgos máximos por objeto.
pub const MAX_FINDINGS: usize = 32;

/// Fuentes documentadas: funciones que devuelven entrada externa.
const SOURCE_FUNCTIONS: &[&str] = &[
    "getcookie",
    "getparameter",
    "getvariable",
    "getremoteaddress",
    "gethostname",
    "getenvironmentvariable",
];

/// Contenedores de request: variables cuyo nombre empieza con estos prefijos
/// son entrada externa.
const SOURCE_CONTAINERS: &[&str] = &["httprequest", "websession", "httpcontext"];

/// Funciones NEUTRAS: propagan el taint sin transformarlo (no son
/// sanitizadores; se modelan sólo para no reportarlas como desconocidas).
const NEUTRAL_FUNCTIONS: &[&str] = &[
    "trim",
    "tostring",
    "tolower",
    "toupper",
    "lower",
    "upper",
    "concat",
    "format",
    "str",
    "string",
    "strcat",
    "substring",
    "replace",
    "length",
    "len",
    "iif",
];

/// Pistas de nombre para clasificar sinks.
const SQL_HINTS: &[&str] = &["sql", "query", "consulta", "sentencia", "select"];
const COMMAND_HINTS: &[&str] = &["cmd", "command", "comando", "shell", "os", "exec"];
const PATH_HINTS: &[&str] = &[
    "file",
    "archivo",
    "path",
    "ruta",
    "directory",
    "carpeta",
    "folder",
];
const OUTPUT_HINTS: &[&str] = &["httpresponse", "webresponse", "response", "html"];

/// Métodos considerados de ejecución SQL/comando.
const EXECUTE_METHODS: &[&str] = &[
    "execute",
    "executedirect",
    "executequery",
    "executescalar",
    "load",
];
/// Métodos considerados de sistema/comando.
const SHELL_METHODS: &[&str] = &["execute", "shell", "run", "system", "cmd", "exec"];
/// Métodos considerados de archivo.
const FILE_METHODS: &[&str] = &[
    "open",
    "create",
    "delete",
    "rename",
    "readline",
    "writeline",
    "read",
    "write",
    "copy",
    "move",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFinding {
    pub line: u32,
    pub cwe: u32,
    pub sink_class: &'static str,
    pub confidence: &'static str,
    pub description: String,
    pub trace: Vec<TraceStep>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaintReport {
    pub findings: Vec<TaintFinding>,
    /// Llamadas no modeladas sobre valores contaminados.
    pub unsupported_sanitizers: usize,
}

#[derive(Debug, Clone)]
struct Call {
    line: u32,
    receiver: Option<String>,
    method: String,
    arg_variables: Vec<String>,
    arg_strings: Vec<String>,
    arg_calls: Vec<String>,
}

fn name_of(token: &Token) -> Option<String> {
    match token.kind {
        TokenKind::Variable | TokenKind::Ident => Some(token.text.to_lowercase()),
        _ => None,
    }
}

fn contains_hint(name: &str, hints: &[&str]) -> bool {
    hints.iter().any(|hint| name.contains(hint))
}

/// Extrae llamadas `metodo(...)` con receptor y argumentos desde los tokens
/// de una línea.
fn calls_in_line(tokens: &[Token]) -> Vec<Call> {
    let mut calls = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let is_call = tokens[index].kind == TokenKind::Ident
            && tokens
                .get(index + 1)
                .map(|t| t.kind == TokenKind::Punct && t.text == "(")
                .unwrap_or(false);
        if !is_call {
            index += 1;
            continue;
        }
        let method = tokens[index].text.to_lowercase();
        let receiver = if index >= 2 && tokens[index - 1].text == "." {
            name_of(&tokens[index - 2])
        } else {
            None
        };
        let mut depth = 0i32;
        let mut close = tokens.len();
        let mut arg_variables = Vec::new();
        let mut arg_strings = Vec::new();
        let mut arg_calls = Vec::new();
        let mut j = index + 1;
        while j < tokens.len() {
            let token = &tokens[j];
            if token.kind == TokenKind::Punct && token.text == "(" {
                depth += 1;
            } else if token.kind == TokenKind::Punct && token.text == ")" {
                depth -= 1;
                if depth == 0 {
                    close = j;
                    break;
                }
            }
            if j > index + 1 && depth >= 1 {
                match token.kind {
                    TokenKind::Variable => {
                        if let Some(name) = name_of(token) {
                            arg_variables.push(name);
                        }
                    }
                    TokenKind::String => {
                        if let Some(value) = token.string_value() {
                            arg_strings.push(value.to_lowercase());
                        }
                    }
                    TokenKind::Ident => {
                        let followed_by_paren = tokens
                            .get(j + 1)
                            .map(|t| t.kind == TokenKind::Punct && t.text == "(")
                            .unwrap_or(false);
                        if followed_by_paren {
                            arg_calls.push(token.text.to_lowercase());
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        calls.push(Call {
            line: tokens[index].line,
            receiver,
            method,
            arg_variables,
            arg_strings,
            arg_calls,
        });
        index = if close > index { close + 1 } else { index + 1 };
    }
    calls
}

fn has_sql_keyword(strings: &[String]) -> bool {
    strings.iter().any(|value| {
        ["select ", "insert ", "update ", "delete ", "where "]
            .iter()
            .any(|keyword| value.contains(keyword))
    })
}

/// Clasifica un sink; `None` si la llamada no es un sink modelado.
fn classify_sink(call: &Call) -> Option<(&'static str, u32)> {
    let receiver = call.receiver.clone().unwrap_or_default();
    let names: Vec<&str> = std::iter::once(receiver.as_str())
        .chain(call.arg_variables.iter().map(String::as_str))
        .filter(|name| !name.is_empty())
        .collect();

    // SQL injection (CWE-89).
    let sql_context = names.iter().any(|name| contains_hint(name, SQL_HINTS))
        || has_sql_keyword(&call.arg_strings);
    if sql_context && EXECUTE_METHODS.contains(&call.method.as_str()) {
        return Some(("sql_injection", 89));
    }
    // OS command injection (CWE-78).
    let command_context = names.iter().any(|name| contains_hint(name, COMMAND_HINTS));
    if command_context && SHELL_METHODS.contains(&call.method.as_str()) {
        return Some(("command_injection", 78));
    }
    // Salida sin codificar (CWE-79).
    if call.method == "write" && names.iter().any(|name| contains_hint(name, OUTPUT_HINTS)) {
        return Some(("unencoded_output", 79));
    }
    // Path traversal (CWE-22).
    let file_context = names.iter().any(|name| contains_hint(name, PATH_HINTS));
    if file_context && FILE_METHODS.contains(&call.method.as_str()) {
        return Some(("path_traversal", 22));
    }
    None
}

/// Línea de la declaración `parm` que contiene la variable.
fn parameter_line(model: &SemanticModel, name: &str) -> u32 {
    let parm_lines: HashSet<u32> = model
        .statements
        .iter()
        .filter(|statement| statement.kind == StatementKind::Parm)
        .map(|statement| statement.line)
        .collect();
    model
        .tokens
        .iter()
        .find(|token| {
            parm_lines.contains(&token.line)
                && token.kind == TokenKind::Variable
                && token.text.to_lowercase() == name
        })
        .map(|token| token.line)
        .unwrap_or(1)
}

/// Analiza taint local intra-objeto (D03).
pub fn analyze_taint(model: &SemanticModel, _text: &str) -> TaintReport {
    // Cobertura incompleta: no se declaran flujos de datos.
    if !model.coverage.complete {
        return TaintReport::default();
    }

    let mut tainted: HashSet<String> = HashSet::new();
    let mut paths: HashMap<String, Vec<TraceStep>> = HashMap::new();

    for parameter in &model.parameters {
        if matches!(
            parameter.direction,
            ParamDirection::In | ParamDirection::InOut
        ) {
            let line = parameter_line(model, &parameter.name);
            tainted.insert(parameter.name.clone());
            paths.insert(
                parameter.name.clone(),
                vec![TraceStep {
                    kind: "source".to_string(),
                    line,
                    detail: format!("parm entrada {}", parameter.name),
                }],
            );
        }
    }
    for token in &model.tokens {
        if token.kind == TokenKind::Variable {
            let name = token.text.to_lowercase();
            if SOURCE_CONTAINERS
                .iter()
                .any(|prefix| name.starts_with(&format!("&{prefix}")))
            {
                tainted.insert(name.clone());
                paths.entry(name.clone()).or_insert_with(|| {
                    vec![TraceStep {
                        kind: "source".to_string(),
                        line: token.line,
                        detail: "request/contenedor externo".to_string(),
                    }]
                });
            }
        }
    }

    let statement_kind: HashMap<u32, StatementKind> = model
        .statements
        .iter()
        .map(|statement| (statement.line, statement.kind))
        .collect();

    // Punto fijo acotado: cada pasada propaga asignaciones en orden.
    let mut unsupported_sanitizers = 0usize;
    // Cada ocurrencia no modelada se cuenta UNA vez (aunque haya N pasadas).
    let mut seen_unsupported: HashSet<(u32, String)> = HashSet::new();
    for _pass in 0..MAX_PASSES {
        let mut changed = false;
        for statement in &model.statements {
            if statement.kind != StatementKind::Assignment {
                continue;
            }
            let line = statement.line;
            let target = model
                .accesses
                .iter()
                .find(|access| access.line == line && access.access == AccessKind::Write)
                .map(|access| access.name.clone());
            let Some(target) = target else { continue };
            let reads: Vec<&str> = model
                .accesses
                .iter()
                .filter(|access| {
                    access.line == line
                        && access.access == AccessKind::Read
                        && access.name != target
                })
                .map(|access| access.name.as_str())
                .collect();
            let tokens: Vec<Token> = model
                .tokens
                .iter()
                .filter(|token| token.line == line)
                .cloned()
                .collect();
            let calls = calls_in_line(&tokens);
            let source_call = calls
                .iter()
                .find(|call| SOURCE_FUNCTIONS.contains(&call.method.as_str()));
            if let Some(call) = source_call {
                if tainted.insert(target.clone()) {
                    changed = true;
                }
                paths.entry(target.clone()).or_insert_with(|| {
                    vec![TraceStep {
                        kind: "source".to_string(),
                        line,
                        detail: format!("{}()", call.method),
                    }]
                });
                continue;
            }
            let Some(parent) = reads
                .iter()
                .filter(|name| tainted.contains(**name))
                .min_by_key(|name| {
                    (
                        paths.get(**name).map(Vec::len).unwrap_or(usize::MAX),
                        name.to_string(),
                    )
                })
            else {
                continue;
            };
            let mut path = paths.get(*parent).cloned().unwrap_or_default();
            let unknown = calls
                .iter()
                .map(|call| &call.method)
                .chain(calls.iter().flat_map(|call| call.arg_calls.iter()))
                .find(|method| !NEUTRAL_FUNCTIONS.contains(&method.as_str()))
                .cloned();
            if let Some(unknown) = unknown {
                if seen_unsupported.insert((line, unknown.clone())) {
                    unsupported_sanitizers += 1;
                }
                path.push(TraceStep {
                    kind: "unsupported_call".to_string(),
                    line,
                    detail: format!("{unknown}() sin semántica de sanitizador modelada"),
                });
            }
            if path.len() < MAX_TRACE {
                path.push(TraceStep {
                    kind: "propagate".to_string(),
                    line,
                    detail: format!("{} = ... {} ...", target, parent),
                });
            }
            if tainted.insert(target.clone()) {
                changed = true;
            }
            paths.entry(target).or_insert(path);
        }
        if !changed {
            break;
        }
    }

    // Detección de sinks sobre el punto fijo.
    let mut findings: Vec<TaintFinding> = Vec::new();
    let mut seen: HashSet<(u32, &'static str)> = HashSet::new();
    let mut lines: Vec<u32> = model
        .tokens
        .iter()
        .map(|token| token.line)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    lines.sort_unstable();
    for line in lines {
        let _ = statement_kind.get(&line);
        let tokens: Vec<Token> = model
            .tokens
            .iter()
            .filter(|token| token.line == line)
            .cloned()
            .collect();
        for call in calls_in_line(&tokens) {
            let Some((class, cwe)) = classify_sink(&call) else {
                continue;
            };
            let tainted_arg = call
                .arg_variables
                .iter()
                .find(|name| tainted.contains(*name))
                .cloned();
            let receiver = call.receiver.clone().filter(|name| tainted.contains(name));
            let source_name = tainted_arg.clone().or_else(|| receiver.clone());
            let Some(source_name) = source_name else {
                continue;
            };
            if !seen.insert((call.line, class)) {
                continue;
            }
            let mut trace = paths.get(&source_name).cloned().unwrap_or_default();
            let unsupported = trace.iter().any(|step| step.kind == "unsupported_call");
            if trace.len() < MAX_TRACE {
                trace.push(TraceStep {
                    kind: "sink".to_string(),
                    line: call.line,
                    detail: format!(
                        "{}{}",
                        call.receiver
                            .as_ref()
                            .map(|receiver| format!("{receiver}."))
                            .unwrap_or_default(),
                        call.method
                    ),
                });
            }
            let confidence = if unsupported {
                "low"
            } else if trace.len() <= 2 {
                "high"
            } else {
                "medium"
            };
            findings.push(TaintFinding {
                line: call.line,
                cwe,
                sink_class: class,
                confidence,
                description: format!(
                    "Posible {} (CWE-{cwe}): el valor de '{source_name}' llega a '{}' sin sanitizador modelado.",
                    class.replace('_', " "),
                    call.method
                ),
                trace,
            });
            if findings.len() >= MAX_FINDINGS {
                return TaintReport {
                    findings,
                    unsupported_sanitizers,
                };
            }
        }
    }

    TaintReport {
        findings,
        unsupported_sanitizers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantics;

    fn taint(source: &str) -> TaintReport {
        let model = semantics::analyze(source);
        analyze_taint(&model, source)
    }

    #[test]
    fn sql_injection_from_parm_is_detected_with_trace() {
        let report = taint(
            "parm(in:&Filtro)\n\
             &sql = 'select * from Cliente where nombre = ' + &Filtro\n\
             &Result = &sql.Execute()\n",
        );
        assert_eq!(report.findings.len(), 1, "{report:?}");
        let finding = &report.findings[0];
        assert_eq!(finding.sink_class, "sql_injection");
        assert_eq!(finding.cwe, 89);
        assert_eq!(finding.confidence, "medium");
        assert_eq!(finding.trace.first().unwrap().kind, "source");
        assert_eq!(finding.trace.last().unwrap().kind, "sink");
        assert_eq!(finding.trace.last().unwrap().line, 3);
        assert_eq!(finding.trace.first().unwrap().line, 1);
    }

    #[test]
    fn parameterized_sql_is_clean() {
        let report = taint(
            "parm(in:&Filtro)\n\
             &sql = 'select * from Cliente where nombre = ?'\n\
             &Result = &sql.Execute()\n",
        );
        assert!(report.findings.is_empty(), "{report:?}");
    }

    #[test]
    fn out_parameters_are_not_sources() {
        let report = taint(
            "parm(out:&Salida)\n\
             &sql = &Salida\n\
             &Result = &sql.Execute()\n",
        );
        assert!(report.findings.is_empty(), "{report:?}");
    }

    #[test]
    fn command_injection_is_detected() {
        let report = taint(
            "parm(in:&Comando)\n\
             &cmd = 'ping ' + &Comando\n\
             &cmd.Execute()\n",
        );
        assert_eq!(report.findings.len(), 1, "{report:?}");
        assert_eq!(report.findings[0].sink_class, "command_injection");
        assert_eq!(report.findings[0].cwe, 78);
    }

    #[test]
    fn path_traversal_is_detected() {
        let report = taint(
            "parm(in:&Ruta)\n\
             &archivo.Open(&Ruta)\n",
        );
        assert_eq!(report.findings.len(), 1, "{report:?}");
        assert_eq!(report.findings[0].sink_class, "path_traversal");
        assert_eq!(report.findings[0].cwe, 22);
    }

    #[test]
    fn unencoded_output_is_detected_from_request_container() {
        let report = taint("&httpResponse.Write(&httpRequest.QueryString)\n");
        assert_eq!(report.findings.len(), 1, "{report:?}");
        assert_eq!(report.findings[0].sink_class, "unencoded_output");
        assert_eq!(report.findings[0].cwe, 79);
    }

    #[test]
    fn unknown_sanitizer_is_conservative_and_visible() {
        let report = taint(
            "parm(in:&Filtro)\n\
             &safe = MiSanitizador(&Filtro)\n\
             &sql = &safe\n\
             &Result = &sql.Execute()\n",
        );
        assert_eq!(report.findings.len(), 1, "{report:?}");
        assert_eq!(report.findings[0].confidence, "low");
        assert!(report.unsupported_sanitizers >= 1);
        assert!(report.findings[0]
            .trace
            .iter()
            .any(|step| step.kind == "unsupported_call"));
    }

    #[test]
    fn trace_length_is_bounded() {
        let mut source = String::from("parm(in:&A0)\n");
        for index in 1..20 {
            source.push_str(&format!("&A{index} = &A{}\n", index - 1));
        }
        source.push_str("&sql = &A19\n&sql.Execute()\n");
        let report = taint(&source);
        assert_eq!(report.findings.len(), 1, "{report:?}");
        assert!(report.findings[0].trace.len() <= MAX_TRACE);
    }

    #[test]
    fn incomplete_coverage_yields_no_dataflow_findings() {
        let model = semantics::analyze("for each Cliente\n    &sql = &Filtro\n");
        let report = analyze_taint(&model, "");
        assert!(report.findings.is_empty());
    }
}
