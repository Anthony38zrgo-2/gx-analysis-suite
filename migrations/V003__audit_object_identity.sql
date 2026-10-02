-- GX-011: identidad de objeto en hallazgos históricos y política/veredicto
-- de la corrida. ALTER TABLE preserva los datos de bases existentes.

ALTER TABLE audit_issues ADD COLUMN object_id      TEXT;
ALTER TABLE audit_issues ADD COLUMN object_type    TEXT;
ALTER TABLE audit_issues ADD COLUMN object_package TEXT;
ALTER TABLE audit_issues ADD COLUMN object_member  TEXT;
ALTER TABLE audit_issues ADD COLUMN object_container TEXT;

ALTER TABLE audit_runs ADD COLUMN policy        TEXT;
ALTER TABLE audit_runs ADD COLUMN verdict       TEXT;
ALTER TABLE audit_runs ADD COLUMN failures_json TEXT;
