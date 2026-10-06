//! gx_sources — descubrimiento de archivos y extracción de objetos GeneXus
//! (B04: adapters de filesystem/ZIP/RAR fuera del dominio `gx_core`).
//!
//! El soporte de paquetes ZIP/RAR vive detrás de la feature `archives`
//! (habilitada por defecto); sin ella sólo se extraen `.txt`/`.xml`.

pub mod filesystem;
pub mod xpz_extractor;
