-- Settings por defecto (equivalente a AuditContext defaults + config/rules.json defaults)
INSERT OR IGNORE INTO app_settings(key, value, value_type, description) VALUES
  ('max_errors', '0', 'integer', 'Umbral máximo errores para Quality Gate CLI'),
  ('max_warnings', '999999', 'integer', 'Umbral máximo warnings para Quality Gate CLI'),
  ('qg_threshold_pct', '10.0', 'float', 'Porcentaje máximo errores/total permitido (GUI)'),
  ('theme', 'dark', 'string', 'Tema GUI: dark|light'),
  ('last_open_dir', '', 'string', 'Último directorio abierto'),
  ('pdf_output_dir', '', 'string', 'Directorio salida PDF, vacío = Downloads'),
  ('engine_version', '1.0.0', 'string', 'Versión engine para trazabilidad'),
  ('seed_csv_hash', '', 'string', 'Hash de Reglas.csv usado para seed');

-- Categorías base (extraídas de Reglas.csv col1)
INSERT OR IGNORE INTO rule_categories(id, name, description, sort_order) VALUES
  ('1', 'Código de programas fuentes - Advertencias', 'Sección 1 Advertencias', 10),
  ('1.4', 'Variables', 'Subcategoría 1.4', 14),
  ('1.6', 'Comentarios', 'Subcategoría 1.6', 16),
  ('1.7', 'Modificaciones/Mantenimiento', 'Subcategoría 1.7', 17),
  ('2.0', 'Mejores Prácticas - Errores', 'Sección 2 Errores', 20),
  ('2.7', 'Iteración y contadores de Variables', 'Subcategoría 2.7', 27);
