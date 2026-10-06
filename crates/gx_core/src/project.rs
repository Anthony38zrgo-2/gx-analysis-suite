//! Análisis project-wide acotado (D04).
//!
//! - Grafo de dependencias por llamadas documentadas `call('Objeto', …)` /
//!   `udp('Objeto', …)` (mapeo POSICIONAL de parámetros según `parm`).
//! - SCCs (Tarjan iterativo) y punto fijo con worklist acotada.
//! - Taint interprocedural por SUMARIOS: un parámetro de entrada que alcanza
//!   un sink dentro del objeto produce un hallazgo cuando un llamador le pasa
//!   un valor contaminado; los parámetros de salida propagan taint de vuelta
//!   al llamador.
//! - Caché incremental por digest de contenido con invalidación INVERSA de
//!   dependientes.
//! - Límites explícitos (nodos, aristas, iteraciones, hallazgos, traza,
//!   bytes de caché): al agotarse se reporta `truncated` y NUNCA se declara
//!   completitud.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::models::TraceStep;
use crate::security::{self, ParamFlow};
use crate::semantics::{self, ParamDirection, SemanticModel, TokenKind};

/// Versión del análisis project-wide (parte de la clave de caché).
pub const PROJECT_VERSION: &str = "gx-project-1";

/// Límites del perfil profundo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectLimits {
    pub max_objects: usize,
    pub max_bytes: usize,
    pub max_edges: usize,
    pub max_iterations: usize,
    pub max_findings: usize,
    pub max_trace: usize,
}

impl Default for ProjectLimits {
    fn default() -> Self {
        ProjectLimits {
            max_objects: 4096,
            max_bytes: 64 * 1024 * 1024,
            max_edges: 16_384,
            max_iterations: 4096,
            max_findings: 256,
            max_trace: security::MAX_TRACE,
        }
    }
}

/// Cobertura y límites alcanzados por el análisis profundo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectCoverage {
    pub objects: usize,
    pub edges: usize,
    pub sccs: usize,
    pub iterations: usize,
    pub truncated: bool,
    pub reason: Option<String>,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub invalidations: usize,
}

/// Hallazgo interprocedural (la identidad completa la resuelve el engine).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectFinding {
    /// Nombre del objeto donde está el sink (normalizado a minúsculas).
    pub object_name: String,
    pub line: u32,
    /// Línea de evidencia (texto crudo del objeto del sink).
    pub line_content: String,
    pub cwe: u32,
    pub sink_class: &'static str,
    pub confidence: &'static str,
    pub description: String,
    pub trace: Vec<TraceStep>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectReport {
    pub findings: Vec<ProjectFinding>,
    pub coverage: ProjectCoverage,
}

/// Entrada del análisis profundo: identidad + texto.
#[derive(Debug, Clone)]
pub struct ProjectInput<'a> {
    pub name: String,
    pub text: &'a str,
}

/// Llamada documentada a otro objeto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub callee: String,
    pub line: u32,
    /// Variables pasadas posicionalmente (sin el nombre del objeto).
    pub args: Vec<String>,
}

/// Sumario reutilizable de un objeto (D04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectSummary {
    pub name: String,
    pub digest: u64,
    pub dependencies: Vec<String>,
    pub calls: Vec<CallSite>,
    pub params: Vec<String>,
    pub param_directions: Vec<ParamDirection>,
    pub flows: ParamFlow,
}

impl ObjectSummary {
    fn approx_bytes(&self) -> usize {
        let mut bytes = self.name.len() + 64;
        for dependency in &self.dependencies {
            bytes += dependency.len() + 16;
        }
        for call in &self.calls {
            bytes += call.callee.len() + 32 + call.args.iter().map(String::len).sum::<usize>();
        }
        for param in &self.params {
            bytes += param.len() + 16;
        }
        bytes += self.flows.sinks.len() * 32 + self.flows.outs.len() * 16;
        bytes
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Clave de digest de un objeto: contenido + parser + engine + versión del
/// análisis + configuración habilitada (D04).
pub fn summary_key(text: &str, config_key: u64) -> u64 {
    let mut hash = fnv1a(text.as_bytes());
    hash ^= fnv1a(semantics::PARSER_VERSION.as_bytes());
    hash ^= fnv1a(env!("CARGO_PKG_VERSION").as_bytes());
    hash ^= fnv1a(PROJECT_VERSION.as_bytes());
    hash ^= config_key;
    hash
}

/// Clave de configuración: ids habilitados (orden-independiente).
pub fn config_key(enabled_rule_ids: &[String]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut ids: Vec<&str> = enabled_rule_ids.iter().map(String::as_str).collect();
    ids.sort_unstable();
    for id in ids {
        hash ^= fnv1a(id.as_bytes());
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Extrae llamadas documentadas a otros objetos (`call`/`udp`) con sus
/// argumentos posicionales.
pub fn extract_calls(model: &SemanticModel) -> Vec<CallSite> {
    let mut calls = Vec::new();
    let mut lines: Vec<u32> = model.tokens.iter().map(|token| token.line).collect();
    lines.sort_unstable();
    lines.dedup();
    for line in lines {
        let tokens: Vec<_> = model
            .tokens
            .iter()
            .filter(|token| token.line == line)
            .cloned()
            .collect();
        for call in security::calls_in_line(&tokens) {
            if call.method != "call" && call.method != "udp" {
                continue;
            }
            // El primer argumento es el nombre del objeto (string literal).
            let Some(callee) = tokens
                .iter()
                .find(|token| token.kind == TokenKind::String)
                .and_then(|token| token.string_value())
                .map(|value| value.trim().to_lowercase())
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            calls.push(CallSite {
                callee,
                line,
                args: call.arg_variables,
            });
        }
    }
    calls
}

/// Construye el sumario de un objeto a partir de su modelo (D04).
pub fn summarize(name: &str, digest: u64, model: &SemanticModel) -> ObjectSummary {
    let calls = extract_calls(model);
    let mut dependencies: Vec<String> = calls.iter().map(|call| call.callee.clone()).collect();
    dependencies.sort();
    dependencies.dedup();
    ObjectSummary {
        name: name.to_lowercase(),
        digest,
        dependencies,
        calls,
        params: model
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .collect(),
        param_directions: model
            .parameters
            .iter()
            .map(|parameter| parameter.direction)
            .collect(),
        flows: security::analyze_param_flows(model),
    }
}

/// Caché acotada de sumarios con invalidación inversa de dependientes (D04).
pub struct SummaryCache {
    entries: HashMap<u64, ObjectSummary>,
    by_name: HashMap<String, u64>,
    reverse: HashMap<String, HashSet<u64>>,
    order: VecDeque<u64>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
}

impl Default for SummaryCache {
    fn default() -> Self {
        SummaryCache::with_limits(256, 8 * 1024 * 1024)
    }
}

impl SummaryCache {
    pub fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        SummaryCache {
            entries: HashMap::new(),
            by_name: HashMap::new(),
            reverse: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            hits: 0,
            misses: 0,
            invalidations: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Devuelve el sumario cacheado o lo computa; `true` si fue hit.
    pub fn get_or_compute(
        &mut self,
        digest: u64,
        name: &str,
        compute: impl FnOnce() -> ObjectSummary,
    ) -> (ObjectSummary, bool) {
        if let Some(summary) = self.entries.get(&digest) {
            self.hits += 1;
            return (summary.clone(), true);
        }
        self.misses += 1;
        let summary = compute();
        self.insert(digest, name, summary.clone());
        (summary, false)
    }

    fn insert(&mut self, digest: u64, name: &str, summary: ObjectSummary) {
        let name = name.to_lowercase();
        // Un mismo nombre con digest nuevo (contenido/config cambiado) invalida
        // la entrada vieja: nunca conviven dos versiones del mismo objeto.
        if let Some(old_digest) = self.by_name.get(&name).copied() {
            if old_digest != digest {
                if let Some(old) = self.entries.remove(&old_digest) {
                    self.bytes = self.bytes.saturating_sub(old.approx_bytes());
                    for dependency in &old.dependencies {
                        if let Some(set) = self.reverse.get_mut(dependency) {
                            set.remove(&old_digest);
                        }
                    }
                }
            }
        }
        let bytes = summary.approx_bytes();
        if let Some(previous) = self.entries.insert(digest, summary) {
            self.bytes = self.bytes.saturating_sub(previous.approx_bytes());
            if let Some(old) = self.by_name.get(&previous.name) {
                if *old == digest {
                    self.by_name.remove(&previous.name);
                }
            }
        }
        self.by_name.insert(name, digest);
        self.order.push_back(digest);
        self.bytes += bytes;
        let current = self.entries.get(&digest).cloned();
        if let Some(current) = current {
            for dependency in &current.dependencies {
                self.reverse
                    .entry(dependency.clone())
                    .or_default()
                    .insert(digest);
            }
        }
        self.enforce_limits();
    }

    fn enforce_limits(&mut self) {
        while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.approx_bytes());
                if let Some(current) = self.by_name.get(&removed.name) {
                    if *current == oldest {
                        self.by_name.remove(&removed.name);
                    }
                }
                for dependency in &removed.dependencies {
                    if let Some(set) = self.reverse.get_mut(dependency) {
                        set.remove(&oldest);
                    }
                }
            }
        }
    }

    /// Invalida los sumarios de los objetos cambiados y de sus dependientes
    /// TRANSITIVOS (aristas inversas); devuelve cuántos sumarios se quitaron.
    pub fn invalidate_dependents(&mut self, changed: &[String]) -> usize {
        let mut to_remove: HashSet<u64> = HashSet::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = changed.iter().map(|name| name.to_lowercase()).collect();
        while let Some(name) = queue.pop_front() {
            if !visited.insert(name.clone()) {
                continue;
            }
            if let Some(digest) = self.by_name.get(&name) {
                to_remove.insert(*digest);
            }
            if let Some(dependents) = self.reverse.get(&name) {
                for digest in dependents {
                    if let Some(summary) = self.entries.get(digest) {
                        queue.push_back(summary.name.clone());
                    }
                }
            }
        }
        let mut removed = 0usize;
        for digest in to_remove {
            if let Some(summary) = self.entries.remove(&digest) {
                self.bytes = self.bytes.saturating_sub(summary.approx_bytes());
                if let Some(current) = self.by_name.get(&summary.name) {
                    if *current == digest {
                        self.by_name.remove(&summary.name);
                    }
                }
                for dependency in &summary.dependencies {
                    if let Some(set) = self.reverse.get_mut(dependency) {
                        set.remove(&digest);
                    }
                }
                removed += 1;
            }
        }
        self.invalidations += removed as u64;
        removed
    }

    /// Dependientes transitivos de un objeto (sin incluir el propio nombre).
    pub fn dependents_of(&self, name: &str) -> Vec<String> {
        let name = name.to_lowercase();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::from([name.clone()]);
        let mut out = Vec::new();
        while let Some(current) = queue.pop_front() {
            if let Some(dependents) = self.reverse.get(&current) {
                for digest in dependents {
                    if let Some(summary) = self.entries.get(digest) {
                        if summary.name != name && visited.insert(summary.name.clone()) {
                            out.push(summary.name.clone());
                            queue.push_back(summary.name.clone());
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }
}

/// Caché global de sumarios entre corridas del mismo proceso (D04).
pub static GLOBAL_PROJECT_CACHE: std::sync::LazyLock<std::sync::Mutex<SummaryCache>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(SummaryCache::default()));

/// Cuenta SCCs (Tarjan iterativo) sobre el grafo de nombres.
fn count_sccs(nodes: &[String], edges: &HashMap<String, Vec<String>>) -> usize {
    let mut index = 0usize;
    let mut indexes: HashMap<&str, usize> = HashMap::new();
    let mut low: HashMap<&str, usize> = HashMap::new();
    let mut on_stack: HashSet<&str> = HashSet::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut components = 0usize;

    for node in nodes {
        if indexes.contains_key(node.as_str()) {
            continue;
        }
        // Tarjan iterativo: (nodo, siguiente hijo a visitar).
        let mut work: Vec<(&str, usize)> = vec![(node.as_str(), 0)];
        while let Some((current, child_index)) = work.pop() {
            if child_index == 0 {
                indexes.insert(current, index);
                low.insert(current, index);
                index += 1;
                stack.push(current);
                on_stack.insert(current);
            }
            let children = edges.get(current).map(Vec::as_slice).unwrap_or(&[]);
            if child_index < children.len() {
                work.push((current, child_index + 1));
                let child = children[child_index].as_str();
                if !indexes.contains_key(child) {
                    work.push((child, 0));
                } else if on_stack.contains(child) {
                    let child_low = *low.get(child).unwrap_or(&usize::MAX);
                    let current_low = *low.get(current).unwrap_or(&usize::MAX);
                    low.insert(current, current_low.min(child_low));
                }
                continue;
            }
            // Cierre del nodo.
            let current_low = *low.get(current).unwrap_or(&usize::MAX);
            if let Some(parent) = work.last().map(|(parent, _)| *parent) {
                let parent_low = *low.get(parent).unwrap_or(&usize::MAX);
                low.insert(parent, parent_low.min(current_low));
            }
            if Some(&current_low) == low.get(current) && Some(&current_low) == indexes.get(current)
            {
                // Raíz de SCC.
                components += 1;
                while let Some(member) = stack.pop() {
                    on_stack.remove(member);
                    if member == current {
                        break;
                    }
                }
            }
        }
    }
    components
}

fn line_text(text: Option<&str>, line: u32) -> String {
    text.and_then(|text| text.split('\n').nth(line.saturating_sub(1) as usize))
        .map(|raw| raw.trim_end_matches('\r').to_string())
        .unwrap_or_default()
}

/// Analiza el proyecto completo con límites y caché (D04).
///
/// `changed` (opcional) permite reutilizar sumarios de objetos no afectados:
/// sólo se procesan los cambiados y sus dependientes transitivos.
pub fn analyze_project(
    inputs: &[ProjectInput<'_>],
    limits: &ProjectLimits,
    config_key: u64,
    cache: &mut SummaryCache,
    changed: Option<&[String]>,
) -> ProjectReport {
    let mut coverage = ProjectCoverage::default();
    let mut findings: Vec<ProjectFinding> = Vec::new();
    let truncate = |reason: String, coverage: &mut ProjectCoverage| {
        coverage.truncated = true;
        coverage.reason = Some(reason);
    };

    if inputs.len() > limits.max_objects {
        truncate(
            format!(
                "proyecto truncado: {} objetos > máximo {}",
                inputs.len(),
                limits.max_objects
            ),
            &mut coverage,
        );
    }
    let invalidations_before = cache.invalidations;
    let mut total_bytes = 0usize;
    let mut texts: HashMap<String, &str> = HashMap::new();
    let mut summaries: HashMap<String, ObjectSummary> = HashMap::new();
    let mut name_order: Vec<String> = Vec::new();

    for input in inputs.iter().take(limits.max_objects) {
        let name = input.name.to_lowercase();
        total_bytes += input.text.len();
        if total_bytes > limits.max_bytes {
            truncate(
                format!(
                    "proyecto truncado: {} bytes > máximo {}",
                    total_bytes, limits.max_bytes
                ),
                &mut coverage,
            );
            break;
        }
        let digest = summary_key(input.text, config_key);
        let (summary, hit) = cache.get_or_compute(digest, &name, || {
            let model = semantics::analyze(input.text);
            summarize(&name, digest, &model)
        });
        if hit {
            coverage.cache_hits += 1;
        } else {
            coverage.cache_misses += 1;
        }
        texts.insert(name.clone(), input.text);
        summaries.insert(name.clone(), summary);
        name_order.push(name);
    }
    coverage.objects = name_order.len();
    // Invalidaciones efectivas durante ESTA corrida (digests reemplazados).
    coverage.invalidations = (cache.invalidations - invalidations_before) as usize;

    // Grafo de dependencias (sólo aristas hacia objetos presentes).
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut edge_count = 0usize;
    'edges: for name in &name_order {
        let Some(summary) = summaries.get(name) else {
            continue;
        };
        for dependency in &summary.dependencies {
            if !summaries.contains_key(dependency) {
                continue;
            }
            if edge_count >= limits.max_edges {
                truncate(
                    format!("proyecto truncado: aristas > máximo {}", limits.max_edges),
                    &mut coverage,
                );
                break 'edges;
            }
            edges
                .entry(name.clone())
                .or_default()
                .push(dependency.clone());
            edge_count += 1;
        }
    }
    coverage.edges = edge_count;
    coverage.sccs = count_sccs(&name_order, &edges);

    // Frontera del proyecto: objetos sin llamadores entrantes tratan sus
    // parámetros In/InOut como fuentes externas.
    let mut incoming: HashMap<String, usize> = HashMap::new();
    for dependencies in edges.values() {
        for dependency in dependencies {
            *incoming.entry(dependency.clone()).or_default() += 1;
        }
    }

    // Punto fijo con worklist acotada (SCCs cubiertas por el tope global).
    let mut tainted_params: HashMap<String, HashSet<usize>> = HashMap::new();
    let mut extra_tainted: HashMap<String, HashSet<String>> = HashMap::new();
    let mut extra_paths: HashMap<String, HashMap<String, Vec<TraceStep>>> = HashMap::new();
    let mut queue: VecDeque<String> = match changed {
        Some(changed) => {
            let mut seed: Vec<String> = changed.iter().map(|name| name.to_lowercase()).collect();
            for name in changed {
                seed.extend(cache.dependents_of(name));
            }
            seed.sort();
            seed.dedup();
            seed.into()
        }
        None => name_order.iter().cloned().collect(),
    };

    'worklist: while let Some(name) = queue.pop_front() {
        if coverage.iterations >= limits.max_iterations {
            truncate(
                format!(
                    "punto fijo no alcanzado: iteraciones > máximo {}",
                    limits.max_iterations
                ),
                &mut coverage,
            );
            break;
        }
        let Some(summary) = summaries.get(&name).cloned() else {
            continue;
        };
        let Some(text) = texts.get(&name).copied() else {
            continue;
        };
        // El modelo semántico se reconstruye SÓLO para objetos procesados;
        // los sumarios de objetos no afectados vienen de la caché.
        let model = semantics::analyze(text);
        coverage.iterations += 1;

        // Estado local: parámetros contaminados por llamadores + variables
        // contaminadas por parámetros de salida de llamadas previas.
        let mut initial: HashSet<String> = extra_tainted.get(&name).cloned().unwrap_or_default();
        let mut paths: HashMap<String, Vec<TraceStep>> =
            extra_paths.get(&name).cloned().unwrap_or_default();
        if incoming.get(&name).copied().unwrap_or(0) == 0 {
            for (index, param) in summary.params.iter().enumerate() {
                if matches!(
                    summary.param_directions.get(index),
                    Some(ParamDirection::In) | Some(ParamDirection::InOut)
                ) {
                    initial.insert(param.clone());
                    paths.entry(param.clone()).or_insert_with(|| {
                        vec![TraceStep {
                            kind: "source".to_string(),
                            line: 1,
                            detail: format!("parm entrada {param} (frontera del proyecto)"),
                        }]
                    });
                }
            }
        }
        if let Some(params) = tainted_params.get(&name) {
            for &param_index in params {
                if let Some(param_name) = summary.params.get(param_index) {
                    initial.insert(param_name.clone());
                    paths.entry(param_name.clone()).or_insert_with(|| {
                        vec![TraceStep {
                            kind: "source".to_string(),
                            line: 1,
                            detail: format!("parm entrada {param_name} (llamador)"),
                        }]
                    });
                }
            }
        }
        let state = security::propagate(&model, initial, paths);

        // Sinks locales alcanzados por el estado extendido.
        for finding in security::detect_sinks(&model, &state.tainted, &state.paths) {
            if findings.len() >= limits.max_findings {
                truncate(
                    format!("hallazgos > máximo {}", limits.max_findings),
                    &mut coverage,
                );
                break 'worklist;
            }
            findings.push(ProjectFinding {
                object_name: name.clone(),
                line: finding.line,
                line_content: line_text(texts.get(&name).copied(), finding.line),
                cwe: finding.cwe,
                sink_class: finding.sink_class,
                confidence: finding.confidence,
                description: finding.description,
                trace: finding.trace,
            });
        }

        // Llamadas: propagación interprocedural por sumarios.
        for call in &summary.calls {
            let Some(callee) = summaries.get(&call.callee) else {
                continue;
            };
            for (position, arg) in call.args.iter().enumerate() {
                if !state.tainted.contains(arg) {
                    continue;
                }
                let mut path = state.paths.get(arg).cloned().unwrap_or_default();
                if path.len() < limits.max_trace {
                    path.push(TraceStep {
                        kind: "call".to_string(),
                        line: call.line,
                        detail: format!("call('{}')", call.callee),
                    });
                }

                // Parámetro del callee contaminado → encolar callee.
                let params = tainted_params.entry(callee.name.clone()).or_default();
                if params.insert(position) {
                    queue.push_back(callee.name.clone());
                }

                // El parámetro alcanza un sink DENTRO del callee.
                for sink in callee
                    .flows
                    .sinks
                    .iter()
                    .filter(|sink| sink.param == position)
                {
                    if findings.len() >= limits.max_findings {
                        truncate(
                            format!("hallazgos > máximo {}", limits.max_findings),
                            &mut coverage,
                        );
                        break 'worklist;
                    }
                    let mut trace = path.clone();
                    if trace.len() < limits.max_trace {
                        trace.push(TraceStep {
                            kind: "sink".to_string(),
                            line: sink.line,
                            detail: format!("{}()", sink.sink_class),
                        });
                    }
                    findings.push(ProjectFinding {
                        object_name: callee.name.clone(),
                        line: sink.line,
                        line_content: line_text(texts.get(&callee.name).copied(), sink.line),
                        cwe: sink.cwe,
                        sink_class: sink.sink_class,
                        confidence: "medium",
                        description: format!(
                            "Posible {} (CWE-{}): '{}' llega al parámetro {} de '{}' desde '{}'.",
                            sink.sink_class.replace('_', " "),
                            sink.cwe,
                            arg,
                            position,
                            callee.name,
                            name
                        ),
                        trace,
                    });
                }

                // Parámetro de salida: el taint vuelve al llamador.
                for out in callee
                    .flows
                    .outs
                    .iter()
                    .filter(|out| out.from_param == position)
                {
                    if let Some(caller_variable) = call.args.get(out.to_param) {
                        let entry = extra_tainted.entry(name.clone()).or_default();
                        if entry.insert(caller_variable.clone()) {
                            let mut return_path = path.clone();
                            if return_path.len() < limits.max_trace {
                                return_path.push(TraceStep {
                                    kind: "propagate".to_string(),
                                    line: call.line,
                                    detail: format!("{caller_variable} ← out de '{}'", call.callee),
                                });
                            }
                            extra_paths
                                .entry(name.clone())
                                .or_default()
                                .entry(caller_variable.clone())
                                .or_insert(return_path);
                            queue.push_back(name.clone());
                        }
                    }
                }
            }
        }
    }

    findings.sort_by(|a, b| {
        (a.object_name.as_str(), a.line, a.cwe).cmp(&(b.object_name.as_str(), b.line, b.cwe))
    });
    findings.dedup_by(|a, b| {
        a.object_name == b.object_name && a.line == b.line && a.sink_class == b.sink_class
    });
    ProjectReport { findings, coverage }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLER: &str = "parm(in:&Entrada)\ncall('ProcSink', &Entrada)\n";
    const SINK: &str = "parm(in:&Valor)\n&sql = 'select * from Cliente where nombre = ' + &Valor\n&sql.Execute()\n";

    fn inputs<'a>(pairs: &'a [(&'a str, &'a str)]) -> Vec<ProjectInput<'a>> {
        pairs
            .iter()
            .map(|(name, text)| ProjectInput {
                name: name.to_string(),
                text,
            })
            .collect()
    }

    #[test]
    fn interprocedural_taint_reaches_callee_sink() {
        let project = inputs(&[("Caller", CALLER), ("ProcSink", SINK)]);
        let mut cache = SummaryCache::default();
        let report = analyze_project(
            &project,
            &ProjectLimits::default(),
            config_key(&["GX.SEC.3".to_string()]),
            &mut cache,
            None,
        );
        assert_eq!(report.findings.len(), 1, "{report:?}");
        let finding = &report.findings[0];
        assert_eq!(finding.object_name, "procsink");
        assert_eq!(finding.cwe, 89);
        assert!(finding.trace.iter().any(|step| step.kind == "call"));
        assert_eq!(finding.trace.last().unwrap().kind, "sink");
        assert_eq!(report.coverage.edges, 1);
        assert_eq!(report.coverage.objects, 2);
    }

    #[test]
    fn out_parameter_returns_taint_to_caller() {
        let builder = "parm(in:&Origen, out:&Destino)\n&Destino = &Origen\n";
        let caller =
            "parm(in:&Entrada)\ncall('ProcBuild', &Entrada, &Salida)\n&sql = &Salida\n&sql.Execute()\n";
        let pairs = [("Caller", caller), ("ProcBuild", builder)];
        let project = inputs(&pairs);
        let mut cache = SummaryCache::default();
        let report = analyze_project(
            &project,
            &ProjectLimits::default(),
            config_key(&[]),
            &mut cache,
            None,
        );
        assert_eq!(report.findings.len(), 1, "{report:?}");
        assert_eq!(report.findings[0].object_name, "caller");
        assert_eq!(report.findings[0].cwe, 89);
        assert!(report.findings[0]
            .trace
            .iter()
            .any(|step| step.kind == "call"));
    }

    #[test]
    fn recursion_is_bounded_and_does_not_hang() {
        let recursive = "parm(in:&X)\ncall('Recursivo', &X)\n&sql = &X\n&sql.Execute()\n";
        let pairs = [("Recursivo", recursive)];
        let project = inputs(&pairs);
        let limits = ProjectLimits {
            max_iterations: 8,
            ..Default::default()
        };
        let mut cache = SummaryCache::default();
        let report = analyze_project(&project, &limits, config_key(&[]), &mut cache, None);
        assert!(report.coverage.iterations <= 8);
        assert_eq!(report.coverage.sccs, 1, "autociclo = 1 SCC");
        assert!(
            report.findings.is_empty(),
            "sin llamador externo no hay taint entrante"
        );
    }

    #[test]
    fn unchanged_summaries_are_reused() {
        let project = inputs(&[("Caller", CALLER), ("ProcSink", SINK)]);
        let mut cache = SummaryCache::default();
        let key = config_key(&[]);
        let first = analyze_project(&project, &ProjectLimits::default(), key, &mut cache, None);
        assert_eq!(first.coverage.cache_misses, 2);
        assert_eq!(first.coverage.cache_hits, 0);
        let second = analyze_project(&project, &ProjectLimits::default(), key, &mut cache, None);
        assert_eq!(second.coverage.cache_hits, 2, "sumarios reutilizados");
        assert_eq!(second.coverage.cache_misses, 0);
        assert_eq!(second.findings, first.findings, "mismo resultado");
    }

    #[test]
    fn changed_dependency_invalidates_transitive_dependents() {
        let project = inputs(&[
            ("A", "parm(in:&X)\ncall('B', &X)\n"),
            ("B", "parm(in:&X)\ncall('C', &X)\n"),
            ("C", "parm(in:&X)\n&sql = &X\n&sql.Execute()\n"),
        ]);
        let mut cache = SummaryCache::default();
        let key = config_key(&[]);
        analyze_project(&project, &ProjectLimits::default(), key, &mut cache, None);
        assert_eq!(cache.len(), 3);

        let dependents = cache.dependents_of("C");
        assert_eq!(dependents, vec!["a".to_string(), "b".to_string()]);
        let removed = cache.invalidate_dependents(&["C".to_string()]);
        assert_eq!(removed, 3, "C y sus dependientes transitivos");
        assert!(cache.is_empty());
    }

    #[test]
    fn limits_truncate_and_never_claim_completion() {
        let project = inputs(&[("Caller", CALLER), ("ProcSink", SINK)]);
        let limits = ProjectLimits {
            max_objects: 1,
            ..Default::default()
        };
        let mut cache = SummaryCache::default();
        let report = analyze_project(&project, &limits, config_key(&[]), &mut cache, None);
        assert!(report.coverage.truncated);
        assert!(report
            .coverage
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("truncado"));
        assert_eq!(report.coverage.objects, 1);
    }

    #[test]
    fn cache_eviction_bounds_bytes_and_entries() {
        let mut cache = SummaryCache::with_limits(2, 1024 * 1024);
        for index in 0..5 {
            let name = format!("Obj{index}");
            let model = semantics::analyze("&x = 1\n");
            cache.get_or_compute(index as u64, &name, || {
                summarize(&name, index as u64, &model)
            });
        }
        assert_eq!(cache.len(), 2, "tope de entradas");
        assert!(cache.bytes() <= 1024 * 1024);
    }

    #[test]
    fn digest_includes_content_and_config() {
        let a = summary_key("&x = 1", config_key(&["GX.SEC.3".to_string()]));
        let b = summary_key("&x = 2", config_key(&["GX.SEC.3".to_string()]));
        let c = summary_key("&x = 1", config_key(&["GX.SEC.2".to_string()]));
        assert_ne!(a, b);
        assert_ne!(a, c, "la configuración habilitada cambia la clave");
    }
}
