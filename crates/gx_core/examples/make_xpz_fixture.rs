//! Genera los fixtures XPZ de regresión (GX-006/GATE-ENGINE).
//!
//! Ejecutar una vez y commitear los artefactos:
//! ```powershell
//! cargo run -p gx_core --example make_xpz_fixture
//! ```
//!
//! - `tests/fixtures/sources/sample_package.xpz` — paquete con 2 objetos
//!   (ProcBueno limpio, ProcMalo con 2 hallazgos en líneas miembro-local).
//! - `tests/fixtures/sources/unusable_package.xpz` — miembro XML sin
//!   bloque <Events> → debe reportarse como layout no soportado.

use std::io::Write;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

const PROC_BUENO: &str = r"
sub 'Iniciar'
    // Inicializa y prepara las variables de salida
    &MiVar = nullvalue(0)
    &Name = &MiVar
    msg(&Name)
endsub
";

const PROC_MALO: &str = r"
&MiVar = 1
sub 'Inicializar'
    // Inicializa sin nullvalue
    &MiVar = &MiVar + 1
endsub
&i = &i + 1
";

fn member_xml(kind: &str, name: &str, package: &str, code: &str) -> Vec<u8> {
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n\
         <{kind} name=\"{name}\" package=\"{package}\">\n\
         <Events>\n<![CDATA[{code}]]>\n</Events>\n\
         </{kind}>\n"
    );
    xml.into_bytes()
}

fn write_member(zw: &mut ZipWriter<std::fs::File>, name: &str, data: &[u8]) {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).expect("fecha fija"));
    zw.start_file(name, options).expect("start_file");
    zw.write_all(data).expect("write_all");
}

fn main() {
    let fixtures = std::path::Path::new("tests/fixtures/sources");
    std::fs::create_dir_all(fixtures).expect("create fixtures dir");

    // sample_package.xpz: 2 miembros con Events CDATA.
    let path = fixtures.join("sample_package.xpz");
    let file = std::fs::File::create(&path).expect("create sample_package.xpz");
    let mut zw = ZipWriter::new(file);
    write_member(
        &mut zw,
        "PkgDemo/ProcBueno.xml",
        &member_xml("Procedure", "ProcBueno", "PkgDemo", PROC_BUENO),
    );
    write_member(
        &mut zw,
        "PkgDemo/ProcMalo.xml",
        &member_xml("Procedure", "ProcMalo", "PkgDemo", PROC_MALO),
    );
    zw.finish().expect("finish sample");
    println!("generado: {}", path.display());

    // unusable_package.xpz: un miembro XML SIN Events.
    let path = fixtures.join("unusable_package.xpz");
    let file = std::fs::File::create(&path).expect("create unusable_package.xpz");
    let mut zw = ZipWriter::new(file);
    let notas = b"<?xml version=\"1.0\"?>\n<Notes>\n<Body>sin codigo</Body>\n</Notes>\n".to_vec();
    write_member(&mut zw, "Notas.xml", &notas);
    zw.finish().expect("finish unusable");
    println!("generado: {}", path.display());
}
