//! Propiedades de la pasada léxica (A03/E01): totalidad y preservación de
//! layout sobre entradas arbitrarias, con un generador determinista (sin
//! dependencias externas para que corra en CI compartido).

use gx_core::lexical::{mask_block_comments, strip_line};

/// Xorshift64* determinista: mismos casos en cada corrida.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

const ALPHABET: &[&str] = &[
    "'", "\"", "/", "*", "\\", "\n", "\r", "\t", " ", "a", "Z", "&", "=", "_", "0", "á", "€", "//",
    "/*", "*/",
];

fn random_input(rng: &mut Rng, max_len: usize) -> String {
    let len = rng.below(max_len + 1);
    let mut out = String::new();
    for _ in 0..len {
        out.push_str(ALPHABET[rng.below(ALPHABET.len())]);
    }
    out
}

/// `mask_block_comments` es total, preserva bytes, líneas y UTF-8.
#[test]
fn mask_block_comments_preserves_layout_for_arbitrary_input() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    for iteration in 0..4000 {
        let input = random_input(&mut rng, 120);
        let masked = mask_block_comments(&input);
        assert_eq!(
            masked.len(),
            input.len(),
            "iteración {iteration}: bytes desplazados para {input:?}"
        );
        assert_eq!(
            masked.matches('\n').count(),
            input.matches('\n').count(),
            "iteración {iteration}: líneas desplazadas para {input:?}"
        );
        assert_eq!(
            masked.matches('\r').count(),
            input.matches('\r').count(),
            "iteración {iteration}: CR desplazados para {input:?}"
        );
    }
}

/// `strip_line` es total y sólo elimina contenido (nunca inventa bytes).
#[test]
fn strip_line_is_total_and_never_grows() {
    let mut rng = Rng(0x0FED_CBA9_8765_4321);
    for iteration in 0..4000 {
        let input = random_input(&mut rng, 120);
        for keep_strings in [false, true] {
            let stripped = strip_line(&input, keep_strings);
            assert!(
                stripped.len() <= input.len(),
                "iteración {iteration} (keep_strings={keep_strings}): creció para {input:?}"
            );
        }
    }
}

/// Casos límite de delimitadores citados (comillas escapadas y sin cierre).
#[test]
fn quoted_delimiters_edge_cases() {
    let cases: &[(&str, &str)] = &[
        ("&x = 'a''b//c'", "&x = 'a''b//c'"),
        (r#"&x = "a""b//c""#, r#"&x = "a""b//c""#),
        ("&x = 'a/*b*/c'", "&x = 'a/*b*/c'"),
        ("&x = '' + 'y'", "&x = '' + 'y'"),
        ("&x = 'sin cierre", "&x = 'sin cierre"),
    ];
    for (input, expected_keep) in cases {
        assert_eq!(
            strip_line(input, true),
            *expected_keep,
            "keep_strings para {input:?}"
        );
        let masked = mask_block_comments(input);
        assert_eq!(masked.len(), input.len(), "máscara para {input:?}");
        assert!(
            !masked.trim().is_empty() || input.trim().is_empty(),
            "la máscara no debe vaciar strings citados: {input:?}"
        );
    }
}
