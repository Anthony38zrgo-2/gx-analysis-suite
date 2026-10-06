//! Pasada léxica string/comment-aware (A03/F03).
//!
//! Reemplaza el enmascarado por regex sobre el texto completo: un scanner
//! único respeta strings (`'...'` y `"..."`), incluye comillas dobles internas
//! (`''` / `""`) y reconoce comentarios `//` y `/* */` fuera de strings.
//!
//! `mask_block_comments` preserva EXACTAMENTE la longitud en bytes y los
//! saltos de línea del texto original: cada byte no-newline dentro de un
//! comentario de bloque se reemplaza por un espacio, de modo que los offsets
//! y números de línea nunca se desplazan.

/// Modo del scanner.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    SingleQuote,
    DoubleQuote,
}

/// Enmascara comentarios de bloque `/* ... */` preservando bytes y líneas.
///
/// - Los strings (`'...'`, `"..."`, con `''`/`""` internas) se respetan:
///   un `/*` dentro de un string NO abre un comentario.
/// - Un bloque sin `*/` de cierre queda intacto (exclusión documentada,
///   igual que la versión anterior).
/// - `//` no se toca aquí: lo elimina el saneado por línea (`strip_line`).
pub fn mask_block_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = bytes.to_vec();
    let mut mode = Mode::Normal;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        match mode {
            Mode::Normal => {
                if b == b'\'' {
                    mode = Mode::SingleQuote;
                    i += 1;
                } else if b == b'"' {
                    mode = Mode::DoubleQuote;
                    i += 1;
                } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                    // Comentario de línea: copiar hasta el salto (los `/*`
                    // dentro de un `//` no abren bloque).
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    match find_block_end(bytes, i + 2) {
                        Some(end) => {
                            blank_span(&mut out, i, end);
                            i = end;
                        }
                        None => {
                            // Sin cierre: no se enmascara (documentado).
                            i += 1;
                        }
                    }
                } else {
                    i += 1;
                }
            }
            Mode::SingleQuote => {
                if b == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        i += 2; // comilla escapada ('' dentro de string)
                    } else {
                        mode = Mode::Normal;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            Mode::DoubleQuote => {
                if b == b'"' {
                    if bytes.get(i + 1) == Some(&b'"') {
                        i += 2;
                    } else {
                        mode = Mode::Normal;
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
        }
    }

    // El enmascarado sólo inserta espacios ASCII: el buffer sigue siendo
    // UTF-8 válido porque los bytes originales nunca se parten.
    String::from_utf8(out).expect("mask_block_comments conserva UTF-8")
}

/// Índice del byte siguiente al `*/` que cierra el bloque abierto en `from`.
fn find_block_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut j = from;
    while j + 1 < bytes.len() {
        if bytes[j] == b'*' && bytes[j + 1] == b'/' {
            return Some(j + 2);
        }
        j += 1;
    }
    None
}

/// Reemplaza por espacios todos los bytes del rango, preservando `\n`/`\r`.
fn blank_span(out: &mut [u8], start: usize, end: usize) {
    for byte in out.iter_mut().take(end).skip(start) {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
}

/// `haystack.contains(needle)` sin distinguir mayúsculas ASCII y sin asignar
/// (B01: evita un `to_lowercase()` por línea).
pub fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// [`strip_line`] sin asignar cuando la línea no contiene comillas ni marcas
/// de comentario (camino típico): devuelve un préstamo del texto (B01).
pub fn strip_line_cow(line: &str, keep_strings: bool) -> std::borrow::Cow<'_, str> {
    if !line
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'\'' | b'"' | b'/'))
    {
        return std::borrow::Cow::Borrowed(line);
    }
    std::borrow::Cow::Owned(strip_line(line, keep_strings))
}

/// Saneado léxico de UNA línea.
///
/// - Siempre elimina comentarios (`//` hasta el final y `/* ... */`).
/// - `keep_strings = false`: elimina también los literales de string completos
///   (vista `clean`, usada para keywords y operadores).
/// - `keep_strings = true`: conserva los literales (vista `code`, necesaria
///   para reglas que inspeccionan valores, p. ej. GX.2.5).
///
/// Respeta comillas dobles internas (`''`/`""`) y no interpreta marcadores
/// dentro de strings.
pub fn strip_line(line: &str, keep_strings: bool) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut mode = Mode::Normal;

    while i < bytes.len() {
        let b = bytes[i];
        match mode {
            Mode::Normal => {
                if b == b'\'' || b == b'"' {
                    let quote = b;
                    mode = if b == b'\'' {
                        Mode::SingleQuote
                    } else {
                        Mode::DoubleQuote
                    };
                    if keep_strings {
                        out.push(char::from(quote));
                    }
                    i += 1;
                } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                    break;
                } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                    match find_block_end(bytes, i + 2) {
                        Some(end) => i = end,
                        None => break,
                    }
                } else {
                    let ch = line[i..].chars().next().expect("frontera de char válida");
                    out.push(ch);
                    i += ch.len_utf8();
                }
            }
            Mode::SingleQuote => {
                if b == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') {
                        if keep_strings {
                            out.push_str("''");
                        }
                        i += 2;
                    } else {
                        mode = Mode::Normal;
                        if keep_strings {
                            out.push('\'');
                        }
                        i += 1;
                    }
                } else {
                    if keep_strings {
                        let ch = line[i..].chars().next().expect("frontera de char válida");
                        out.push(ch);
                        i += ch.len_utf8();
                    } else {
                        i += 1;
                    }
                }
            }
            Mode::DoubleQuote => {
                if b == b'"' {
                    if bytes.get(i + 1) == Some(&b'"') {
                        if keep_strings {
                            out.push_str("\"\"");
                        }
                        i += 2;
                    } else {
                        mode = Mode::Normal;
                        if keep_strings {
                            out.push('"');
                        }
                        i += 1;
                    }
                } else {
                    if keep_strings {
                        let ch = line[i..].chars().next().expect("frontera de char válida");
                        out.push(ch);
                        i += ch.len_utf8();
                    } else {
                        i += 1;
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_comment_inside_string_is_not_masked() {
        let src = "&x = '/* no comentario */' // real";
        let masked = mask_block_comments(src);
        assert_eq!(masked, src, "el bloque está dentro de un string");
    }

    #[test]
    fn block_comment_is_masked_and_length_preserved() {
        let src = "a\n/* bloque\nfor each Customer\n&i = &i + 1\nendfor\n*/\nb";
        let masked = mask_block_comments(src);
        assert_eq!(masked.len(), src.len(), "los offsets no se desplazan");
        assert_eq!(masked.matches('\n').count(), src.matches('\n').count());
        assert!(!masked.contains("for each Customer"));
        assert!(masked.starts_with("a\n"));
        assert!(masked.ends_with("\nb"));
    }

    #[test]
    fn doubled_quotes_do_not_close_string() {
        let src = "&x = 'O''Brien /* sigue string */' /* comentario */";
        let masked = mask_block_comments(src);
        assert!(masked.contains("O''Brien"));
        assert!(!masked.contains("comentario"));
    }

    #[test]
    fn quoted_slashes_are_not_comments() {
        let src = r#"&x = "http://ejemplo" // real"#;
        let masked = mask_block_comments(src);
        assert_eq!(masked, src);
    }

    #[test]
    fn strip_line_removes_comments_keeps_or_drops_strings() {
        let line = r#"&x = 'Admin' // comentario"#;
        assert_eq!(strip_line(line, false), "&x =  ");
        assert_eq!(strip_line(line, true), "&x = 'Admin' ");
    }

    #[test]
    fn strip_line_handles_doubled_quotes_in_literal() {
        let line = "where Name = 'O''Brien'";
        assert_eq!(strip_line(line, true), "where Name = 'O''Brien'");
    }

    #[test]
    fn unclosed_block_comment_is_left_intact() {
        let src = "a /* sin cierre\nb";
        assert_eq!(mask_block_comments(src), src);
    }
}
