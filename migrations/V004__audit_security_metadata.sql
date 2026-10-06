-- D03: metadatos de seguridad en hallazgos (categoría, confianza, CWE).
-- ALTER TABLE preserva los datos existentes.

ALTER TABLE audit_issues ADD COLUMN category   TEXT;
ALTER TABLE audit_issues ADD COLUMN confidence TEXT;
ALTER TABLE audit_issues ADD COLUMN cwe        INTEGER;
