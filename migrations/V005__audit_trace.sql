-- D03: trazas acotadas source→sink de hallazgos de dataflow.
-- ALTER TABLE preserva los datos existentes.

ALTER TABLE audit_issues ADD COLUMN trace_json TEXT;
