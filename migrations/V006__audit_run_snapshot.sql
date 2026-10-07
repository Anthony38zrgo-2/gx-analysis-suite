-- C01: snapshot completo de la corrida de auditoría.
-- - scanned_files: archivos REALMENTE escaneados (no sólo los declarados).
-- - completion: complete/partial/cancelled/failed (el historial distingue
--   corridas incompletas de completas).
-- - coverage_json: ScanCoverage serializado.
-- - request_json: configuración efectiva completa (reglas, política,
--   discovery, flags) tal como se ejecutó.
-- - parser_version / schema_version: parser semántico y contrato del
--   resultado; engine_version ya existe (V001).
-- ALTER TABLE preserva los datos existentes.

ALTER TABLE audit_runs ADD COLUMN scanned_files  INTEGER;
ALTER TABLE audit_runs ADD COLUMN completion     TEXT;
ALTER TABLE audit_runs ADD COLUMN coverage_json  TEXT;
ALTER TABLE audit_runs ADD COLUMN request_json   TEXT;
ALTER TABLE audit_runs ADD COLUMN parser_version TEXT;
ALTER TABLE audit_runs ADD COLUMN schema_version INTEGER;
