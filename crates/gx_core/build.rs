//! Linkeo de librerías de sistema requeridas por `unrar_sys` en Windows.
//!
//! El crate `unrar_sys` (UnRAR vendored) referencia APIs de registro,
//! tokens y criptografía, pero no emite las libs de importación
//! correspondientes. Sin esto, los binarios que NO arrastran esas libs por
//! otra dependencia (tests de gx_core, examples) fallan el linkeo con
//! LNK2019 (RegCloseKey, CryptAcquireContextW, OpenProcessToken, …).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=userenv");
    }
}
