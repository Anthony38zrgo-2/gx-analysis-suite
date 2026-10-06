//! Modelo semántico mínimo GeneXus (D02): tokens, statements con anidamiento,
//! binding de variables/parámetros y def-use local.
//!
//! Sin dependencias nuevas y con recuperación explícita: la cobertura reporta
//! bloques sin cerrar y líneas malformadas, de modo que un input inválido
//! nunca se presenta como análisis semántico completo.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use crate::lexical;

/// Versión del parser semántico: parte de la clave de caché (D04).
pub const PARSER_VERSION: &str = "gx-sem-1";

/// Bits de hechos requeridos por packs/reglas (D01).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FactSet(u32);

impl FactSet {
    pub const NONE: FactSet = FactSet(0);
    pub const TOKENS: FactSet = FactSet(1);
    pub const SYNTAX: FactSet = FactSet(2);
    pub const SYMBOLS: FactSet = FactSet(4);
    pub const DEF_USE: FactSet = FactSet(8);

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: FactSet) -> FactSet {
        FactSet(self.0 | other.0)
    }

    pub const fn contains(self, other: FactSet) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// ¿Necesita el modelo semántico completo (statements/símbolos/def-use)?
    pub const fn needs_model(self) -> bool {
        (self.0 & (Self::SYNTAX.0 | Self::SYMBOLS.0 | Self::DEF_USE.0)) != 0
    }

    /// ¿Necesita tokens?
    pub const fn needs_tokens(self) -> bool {
        (self.0 & Self::TOKENS.0) != 0 || self.needs_model()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Variable,
    Ident,
    String,
    Number,
    Operator,
    Keyword,
    Punct,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    /// Texto del token (las variables incluyen `&`; los strings, comillas).
    pub text: String,
    /// Línea 1-based del texto del objeto.
    pub line: u32,
    /// Posición global (para ordenar accesos de forma estable).
    pub order: usize,
}

impl Token {
    /// Contenido de un literal de string (sin comillas, `''`/`""` resueltas).
    pub fn string_value(&self) -> Option<String> {
        if self.kind != TokenKind::String || self.text.len() < 2 {
            return None;
        }
        let quote = self.text.chars().next()?;
        let inner = &self.text[quote.len_utf8()..self.text.len() - quote.len_utf8()];
        Some(match quote {
            '\'' => inner.replace("''", "'"),
            '"' => inner.replace("\"\"", "\""),
            _ => inner.to_string(),
        })
    }

    /// `true` si es un literal de string no vacío.
    pub fn is_non_empty_string(&self) -> bool {
        self.string_value()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    ForEach,
    EndFor,
    If,
    ElseIf,
    Else,
    EndIf,
    DoCase,
    Case,
    Otherwise,
    EndCase,
    Sub,
    EndSub,
    Where,
    DefinedBy,
    Order,
    Parm,
    Assignment,
    Call,
    Other,
}

impl StatementKind {
    /// Apertura de bloque (requiere cierre).
    pub fn opens_block(self) -> bool {
        matches!(
            self,
            StatementKind::ForEach | StatementKind::If | StatementKind::DoCase | StatementKind::Sub
        )
    }

    /// Cierre de bloque y el tipo de apertura que cierra.
    pub fn closes_block(self) -> Option<StatementKind> {
        match self {
            StatementKind::EndFor => Some(StatementKind::ForEach),
            StatementKind::EndIf => Some(StatementKind::If),
            StatementKind::EndCase => Some(StatementKind::DoCase),
            StatementKind::EndSub => Some(StatementKind::Sub),
            _ => None,
        }
    }

    /// Línea de condición: `=` se interpreta como comparación.
    pub fn is_condition(self) -> bool {
        matches!(
            self,
            StatementKind::If
                | StatementKind::ElseIf
                | StatementKind::Where
                | StatementKind::Case
                | StatementKind::DefinedBy
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub kind: StatementKind,
    /// Línea 1-based del texto del objeto.
    pub line: u32,
    /// Profundidad de anidamiento (0 = nivel superior).
    pub depth: usize,
    /// Índice del statement contenedor (apertura de bloque).
    pub parent: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariableAccess {
    pub name: String,
    pub line: u32,
    pub order: usize,
    pub access: AccessKind,
    /// El acceso ocurre en una condición (`if`/`where`/`case`/`defined by`).
    pub in_condition: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamDirection {
    In,
    Out,
    InOut,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parameter {
    pub name: String,
    pub direction: ParamDirection,
}

/// Cobertura del análisis semántico (D02): lo incompleto es explícito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticCoverage {
    pub unclosed_blocks: usize,
    pub malformed_lines: usize,
    pub complete: bool,
}

impl Default for SemanticCoverage {
    fn default() -> Self {
        SemanticCoverage {
            unclosed_blocks: 0,
            malformed_lines: 0,
            complete: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SemanticModel {
    pub tokens: Vec<Token>,
    pub statements: Vec<Statement>,
    pub accesses: Vec<VariableAccess>,
    pub parameters: Vec<Parameter>,
    pub coverage: SemanticCoverage,
}

impl SemanticModel {
    /// Escrituras de variable nunca leídas antes de la siguiente escritura,
    /// excluyendo parámetros Out/Inout (externamente consumidos) y el patrón
    /// de autoincremento (`&x = &x + 1`, que sí lee).
    pub fn dead_stores(&self) -> Vec<&VariableAccess> {
        let out_parameters: Vec<&str> = self
            .parameters
            .iter()
            .filter(|parameter| {
                matches!(
                    parameter.direction,
                    ParamDirection::Out | ParamDirection::InOut
                )
            })
            .map(|parameter| parameter.name.as_str())
            .collect();

        let mut by_variable: HashMap<&str, Vec<&VariableAccess>> = HashMap::new();
        for access in &self.accesses {
            by_variable
                .entry(access.name.as_str())
                .or_default()
                .push(access);
        }

        // ¿La escritura es read-modify-write (`&x = &x + 1`)? En ese caso el
        // valor previo SÍ se consume y la escritura previa no es dead.
        let is_rmw = |write: &VariableAccess| {
            self.accesses.iter().any(|access| {
                access.name == write.name
                    && access.line == write.line
                    && access.access == AccessKind::Read
                    && access.order > write.order
            })
        };

        let mut dead: Vec<&VariableAccess> = Vec::new();
        for (name, accesses) in by_variable {
            if out_parameters.contains(&name) {
                continue;
            }
            let mut ordered = accesses;
            ordered.sort_by_key(|access| access.order);
            let mut previous_write: Option<&VariableAccess> = None;
            for access in ordered {
                match access.access {
                    AccessKind::Read => previous_write = None,
                    AccessKind::Write => {
                        if is_rmw(access) {
                            // El valor previo se lee en la misma sentencia.
                            previous_write = Some(access);
                            continue;
                        }
                        if let Some(previous) = previous_write.take() {
                            if !previous.in_condition {
                                dead.push(previous);
                            }
                        }
                        previous_write = Some(access);
                    }
                }
            }
        }
        dead.sort_by_key(|access| access.order);
        dead
    }
}

/// Keywords reconocidas (minúsculas) para clasificar statements.
static KEYWORDS: &[&str] = &[
    "for",
    "each",
    "endfor",
    "if",
    "elseif",
    "else",
    "endif",
    "do",
    "case",
    "otherwise",
    "endcase",
    "sub",
    "endsub",
    "where",
    "defined",
    "by",
    "order",
    "parm",
    "in",
    "out",
    "inout",
    "not",
    "and",
    "or",
    "like",
    "true",
    "false",
    "nullvalue",
    "new",
    "is",
];

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_char(c: char) -> bool {
    // El punto NO forma parte del identificador: `&sql.Execute()` debe
    // tokenizarse como variable + método para el dataflow (D03).
    c.is_alphanumeric() || c == '_'
}

/// Tokeniza una línea (sin comentarios, con strings). `order` es la posición
/// global acumulada por el llamador.
fn tokenize_line(line: &str, line_number: u32, order: &mut usize, out: &mut Vec<Token>) {
    let code = lexical::strip_line(line, true);
    let chars: Vec<char> = code.chars().collect();
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if c.is_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        let (kind, text) = if c == '&' {
            index += 1;
            while index < chars.len() && is_ident_char(chars[index]) {
                index += 1;
            }
            (TokenKind::Variable, chars[start..index].iter().collect())
        } else if c == '\'' || c == '"' {
            let quote = c;
            index += 1;
            while index < chars.len() {
                if chars[index] == quote {
                    if index + 1 < chars.len() && chars[index + 1] == quote {
                        index += 2; // comilla escapada
                        continue;
                    }
                    index += 1;
                    break;
                }
                index += 1;
            }
            (TokenKind::String, chars[start..index].iter().collect())
        } else if c.is_ascii_digit() {
            index += 1;
            while index < chars.len() && (chars[index].is_ascii_digit() || chars[index] == '.') {
                index += 1;
            }
            (TokenKind::Number, chars[start..index].iter().collect())
        } else if is_ident_start(c) {
            index += 1;
            while index < chars.len() && is_ident_char(chars[index]) {
                index += 1;
            }
            let text: String = chars[start..index].iter().collect();
            if KEYWORDS.contains(&text.to_lowercase().as_str()) {
                (TokenKind::Keyword, text)
            } else {
                (TokenKind::Ident, text)
            }
        } else if matches!(c, '<' | '>' | '=' | '!') {
            index += 1;
            if index < chars.len() && matches!(chars[index], '=' | '>') {
                index += 1;
            }
            (TokenKind::Operator, chars[start..index].iter().collect())
        } else if matches!(c, '+' | '-' | '*' | '/') {
            index += 1;
            (TokenKind::Operator, chars[start..index].iter().collect())
        } else {
            index += 1;
            (TokenKind::Punct, chars[start..index].iter().collect())
        };
        out.push(Token {
            kind,
            text,
            line: line_number,
            order: *order,
        });
        *order += 1;
    }
}

fn lower(token: &Token) -> String {
    token.text.to_lowercase()
}

fn is_keyword(token: &Token, keyword: &str) -> bool {
    token.kind == TokenKind::Keyword && lower(token) == keyword
}

/// Clasifica la línea por su primer keyword/estructura.
fn classify(tokens: &[Token]) -> StatementKind {
    let first = tokens.first();
    let Some(first) = first else {
        return StatementKind::Other;
    };
    let second = tokens.get(1);
    let third = tokens.get(2);
    if is_keyword(first, "for") {
        if let Some(second) = second {
            if is_keyword(second, "each") {
                return StatementKind::ForEach;
            }
        }
    }
    if is_keyword(first, "endfor") {
        return StatementKind::EndFor;
    }
    if is_keyword(first, "if") {
        return StatementKind::If;
    }
    if is_keyword(first, "elseif")
        || (is_keyword(first, "else") && second.map(|t| is_keyword(t, "if")).unwrap_or(false))
    {
        return StatementKind::ElseIf;
    }
    if is_keyword(first, "else") {
        return StatementKind::Else;
    }
    if is_keyword(first, "endif")
        || (is_keyword(first, "end") && second.map(|t| is_keyword(t, "if")).unwrap_or(false))
    {
        return StatementKind::EndIf;
    }
    if is_keyword(first, "do") && second.map(|t| is_keyword(t, "case")).unwrap_or(false) {
        return StatementKind::DoCase;
    }
    if is_keyword(first, "case") {
        return StatementKind::Case;
    }
    if is_keyword(first, "otherwise") {
        return StatementKind::Otherwise;
    }
    if is_keyword(first, "endcase")
        || (is_keyword(first, "end") && second.map(|t| is_keyword(t, "case")).unwrap_or(false))
    {
        return StatementKind::EndCase;
    }
    if is_keyword(first, "sub") {
        return StatementKind::Sub;
    }
    if is_keyword(first, "endsub") {
        return StatementKind::EndSub;
    }
    if is_keyword(first, "where") {
        return StatementKind::Where;
    }
    if is_keyword(first, "defined") && second.map(|t| is_keyword(t, "by")).unwrap_or(false) {
        return StatementKind::DefinedBy;
    }
    if is_keyword(first, "order") {
        return StatementKind::Order;
    }
    if is_keyword(first, "parm") {
        return StatementKind::Parm;
    }
    // Asignación: `&var = ...` (con `=` de asignación, no comparación).
    if first.kind == TokenKind::Variable
        && second
            .map(|t| t.kind == TokenKind::Operator && t.text == "=")
            .unwrap_or(false)
    {
        return StatementKind::Assignment;
    }
    // Llamada: `do 'nombre'` u `objeto.metodo(...)`.
    if is_keyword(first, "do") {
        return StatementKind::Call;
    }
    if first.kind == TokenKind::Ident
        && second
            .map(|t| t.kind == TokenKind::Punct && t.text == "(")
            .unwrap_or(false)
    {
        return StatementKind::Call;
    }
    if third.is_some() && first.kind == TokenKind::Ident {
        return StatementKind::Other;
    }
    StatementKind::Other
}

/// Extrae variables accedidas en una línea, marcando el target de asignación
/// como Write y el resto como Read.
fn collect_accesses(tokens: &[Token], kind: StatementKind, accesses: &mut Vec<VariableAccess>) {
    let in_condition = kind.is_condition();
    let mut assignment_target_seen = false;
    for token in tokens {
        if token.kind != TokenKind::Variable {
            continue;
        }
        let is_target = kind == StatementKind::Assignment && !assignment_target_seen;
        if is_target {
            assignment_target_seen = true;
        }
        accesses.push(VariableAccess {
            name: lower(token),
            line: token.line,
            order: token.order,
            access: if is_target {
                AccessKind::Write
            } else {
                AccessKind::Read
            },
            in_condition,
        });
    }
}

/// Direcciones de `parm(...)`: soporta `in:&x` y `&x in`.
fn collect_parameters(tokens: &[Token]) -> Vec<Parameter> {
    let mut parameters: Vec<Parameter> = Vec::new();
    let mut pending_direction: Option<ParamDirection> = None;
    let mut last_variable: Option<usize> = None;
    for token in tokens {
        let lowered = lower(token);
        match token.kind {
            TokenKind::Keyword => match lowered.as_str() {
                "in" => pending_direction = Some(ParamDirection::In),
                "out" => pending_direction = Some(ParamDirection::Out),
                "inout" => pending_direction = Some(ParamDirection::InOut),
                _ => {}
            },
            TokenKind::Punct if token.text == ":" => {
                // `in:&x`: la dirección aplica a la variable siguiente.
            }
            TokenKind::Variable => {
                let direction = if let Some(direction) = pending_direction.take() {
                    direction
                } else {
                    ParamDirection::Unspecified
                };
                parameters.push(Parameter {
                    name: lowered,
                    direction,
                });
                last_variable = Some(parameters.len() - 1);
            }
            TokenKind::Ident | TokenKind::Punct => {
                // `&x in` (postfijo): si ya vimos la variable y no hay
                // dirección pendiente, la palabra siguiente la califica.
                if let (Some(index), Some(direction)) = (last_variable, pending_direction.take()) {
                    parameters[index].direction = direction;
                }
            }
            _ => {}
        }
    }
    parameters
}

/// Analiza el texto completo de un objeto.
pub fn analyze(text: &str) -> SemanticModel {
    let mut model = SemanticModel::default();
    let mut order = 0usize;
    let mut stack: Vec<usize> = Vec::new();
    let mut malformed = 0usize;

    for (index, raw_line) in text.split('\n').enumerate() {
        let line_number = index as u32 + 1;
        let line = raw_line.trim_end_matches('\r');
        let mut tokens: Vec<Token> = Vec::new();
        tokenize_line(line, line_number, &mut order, &mut tokens);
        if tokens.is_empty() {
            continue;
        }
        model.tokens.extend(tokens.iter().cloned());

        let kind = classify(&tokens);
        let statement_index = model.statements.len();
        let parent = stack.last().copied();
        model.statements.push(Statement {
            kind,
            line: line_number,
            depth: stack.len(),
            parent,
        });

        collect_accesses(&tokens, kind, &mut model.accesses);
        if kind == StatementKind::Parm {
            model.parameters.extend(collect_parameters(&tokens));
        }

        if kind.opens_block() {
            stack.push(statement_index);
        } else if let Some(expected) = kind.closes_block() {
            match stack.pop() {
                Some(open_index) if model.statements[open_index].kind == expected => {}
                Some(_) | None => malformed += 1,
            }
        }
    }

    model.coverage = SemanticCoverage {
        unclosed_blocks: stack.len(),
        malformed_lines: malformed,
        complete: stack.is_empty() && malformed == 0,
    };
    model
}

/// Clave de caché de hechos (D04): contenido + versión del parser + hechos.
pub fn fact_key(text: &str, facts: FactSet) -> u64 {
    fn fnv1a(bytes: &[u8]) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }
    let mut hash = fnv1a(text.as_bytes());
    hash ^= fnv1a(PARSER_VERSION.as_bytes());
    hash ^= fnv1a(env!("CARGO_PKG_VERSION").as_bytes());
    hash ^= facts.bits() as u64;
    hash
}

/// Caché acotada de modelos semánticos (D04): memoriza por clave de
/// contenido/versión/hechos y reporta hits/misses/evictions.
pub struct FactCache {
    entries: HashMap<u64, std::sync::Arc<SemanticModel>>,
    order: VecDeque<u64>,
    max_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl Default for FactCache {
    fn default() -> Self {
        Self::with_capacity(64)
    }
}

impl FactCache {
    pub fn with_capacity(max_entries: usize) -> Self {
        FactCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_entries: max_entries.max(1),
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    /// Devuelve el modelo cacheado o lo construye; `true` si fue hit.
    pub fn get_or_build(
        &mut self,
        text: &str,
        facts: FactSet,
    ) -> (std::sync::Arc<SemanticModel>, bool) {
        let key = fact_key(text, facts);
        if let Some(model) = self.entries.get(&key) {
            self.hits += 1;
            crate::stats::count_fact_cache_hit();
            return (model.clone(), true);
        }
        self.misses += 1;
        crate::stats::count_fact_cache_miss();
        let model = std::sync::Arc::new(analyze(text));
        if self.entries.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                if self.entries.remove(&oldest).is_some() {
                    self.evictions += 1;
                    crate::stats::count_fact_cache_eviction();
                }
            }
        }
        self.entries.insert(key, model.clone());
        self.order.push_back(key);
        (model, false)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Caché global de hechos: el engine la usa entre corridas del mismo proceso
/// (los benchmarks miden cold/warm hits, D04).
pub static GLOBAL_FACT_CACHE: LazyLock<std::sync::Mutex<FactCache>> =
    LazyLock::new(|| std::sync::Mutex::new(FactCache::default()));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_blocks_and_parents() {
        let model = analyze(
            "for each Customer\n\
             \x20   if &x > 1\n\
             \x20       &y = &x + 1\n\
             \x20   endif\n\
             endfor\n",
        );
        assert!(model.coverage.complete, "{:?}", model.coverage);
        let kinds: Vec<StatementKind> = model.statements.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            vec![
                StatementKind::ForEach,
                StatementKind::If,
                StatementKind::Assignment,
                StatementKind::EndIf,
                StatementKind::EndFor
            ]
        );
        assert_eq!(model.statements[2].depth, 2);
        assert_eq!(model.statements[2].parent, Some(1));
    }

    #[test]
    fn assignment_versus_comparison() {
        let model = analyze("&x = 1\nif &x = 1\nendif\n");
        let writes: Vec<&VariableAccess> = model
            .accesses
            .iter()
            .filter(|a| a.access == AccessKind::Write)
            .collect();
        assert_eq!(writes.len(), 1, "sólo la asignación es escritura");
        assert_eq!(writes[0].line, 1);
        let condition_reads: Vec<&VariableAccess> =
            model.accesses.iter().filter(|a| a.in_condition).collect();
        assert_eq!(condition_reads.len(), 1);
        assert_eq!(condition_reads[0].line, 2);
    }

    #[test]
    fn parameter_directions_out_are_not_dead() {
        let model = analyze("parm(out:&Resultado, in:&Entrada)\n&Resultado = 1\n");
        let out = model
            .parameters
            .iter()
            .find(|p| p.name == "&resultado")
            .unwrap();
        assert_eq!(out.direction, ParamDirection::Out);
        assert!(
            model.dead_stores().is_empty(),
            "un Out consumido externamente no es dead store"
        );
    }

    #[test]
    fn dead_store_is_detected_once() {
        let model = analyze("&x = 1\n&x = 2\n&y = &x\n");
        let dead = model.dead_stores();
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].line, 1);
        assert_eq!(dead[0].name, "&x");
    }

    #[test]
    fn unclosed_block_is_explicit_coverage() {
        let model = analyze("for each Customer\n    &x = 1\n");
        assert!(!model.coverage.complete);
        assert_eq!(model.coverage.unclosed_blocks, 1);
    }

    #[test]
    fn multiline_expression_reads_are_captured() {
        let model = analyze("&total = &a + &b\n");
        let reads: Vec<&str> = model
            .accesses
            .iter()
            .filter(|a| a.access == AccessKind::Read)
            .map(|a| a.name.as_str())
            .collect();
        assert_eq!(reads, vec!["&a", "&b"]);
    }

    #[test]
    fn fact_cache_reports_hits_and_bounds_entries() {
        let mut cache = FactCache::with_capacity(1);
        let (_, hit) = cache.get_or_build("&x = 1", FactSet::DEF_USE);
        assert!(!hit);
        let (_, hit) = cache.get_or_build("&x = 1", FactSet::DEF_USE);
        assert!(hit);
        cache.get_or_build("&y = 2", FactSet::DEF_USE);
        assert_eq!(cache.len(), 1, "la caché está acotada");
        assert_eq!(cache.evictions, 1);
        assert_eq!(cache.hits, 1);
        assert_eq!(cache.misses, 2);
    }

    #[test]
    fn fact_key_includes_facts_and_version() {
        let a = fact_key("&x = 1", FactSet::TOKENS);
        let b = fact_key("&x = 1", FactSet::DEF_USE);
        let c = fact_key("&x = 2", FactSet::TOKENS);
        assert_ne!(a, b, "los hechos requeridos cambian la clave");
        assert_ne!(a, c, "el contenido cambia la clave");
    }
}
