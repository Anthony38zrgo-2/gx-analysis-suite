// GENERADO por desktop/src-tauri/tests/contract_samples.rs — no editar a mano.
// El type-check de Vue falla si el schema Rust driftea de estos tipos.

import type {
  AnalysisRequest,
  AnalysisResult,
  FindingsPage,
  HistoryIssuesPage,
  ObjectWindow,
  ScanSummary,
} from "./types";

export const requestSample: AnalysisRequest = {
  "enabled_rule_ids": [
    "GX.1.1",
    "GX.2.5"
  ],
  "inputs": [
    "tests/fixtures/sources/sample_package.xpz"
  ],
  "policy": {
    "kind": "percentage",
    "max_error_pct": 10.0
  },
  "record_history": false,
  "schema_version": 1
};

export const resultSample: AnalysisResult = {
  "completion": "complete",
  "coverage": {
    "files_deduplicated": 0,
    "files_discovered": 1,
    "files_excluded": 0,
    "inputs_declared": 1,
    "inputs_scanned": 1,
    "source_free_inputs": 0
  },
  "failures": [],
  "findings": [
    {
      "description": "Mala práctica de mantenibilidad: valor en código duro.",
      "file_path": "tests/fixtures/sources/sample_package.xpz",
      "line_content": "where CustomerType = \"VIP\"",
      "line_number": 63,
      "object": {
        "container_path": "tests/fixtures/sources/sample_package.xpz",
        "id": "ProcMalo",
        "member": "PkgDemo/ProcMalo.xml",
        "object_type": "Procedure",
        "package": "PkgDemo"
      },
      "rule_id": "GX.2.5",
      "severity": "ERROR"
    }
  ],
  "metrics": {
    "errors": 1,
    "info": 0,
    "total_findings": 1,
    "warnings": 0
  },
  "policy": {
    "kind": "percentage",
    "max_error_pct": 10.0
  },
  "request": {
    "enabled_rule_ids": [
      "GX.1.1",
      "GX.2.5"
    ],
    "inputs": [
      "tests/fixtures/sources/sample_package.xpz"
    ],
    "policy": {
      "kind": "percentage",
      "max_error_pct": 10.0
    },
    "record_history": false,
    "schema_version": 1
  },
  "scanned_files": 1,
  "schema_version": 1,
  "verdict": "reject"
};

export const summarySample: ScanSummary = {
  "completion": "complete",
  "coverage": {
    "files_deduplicated": 0,
    "files_discovered": 1,
    "files_excluded": 0,
    "inputs_declared": 1,
    "inputs_scanned": 1,
    "source_free_inputs": 0
  },
  "failures": [],
  "findings_total": 1,
  "history_error": null,
  "metrics": {
    "errors": 1,
    "info": 0,
    "total_findings": 1,
    "warnings": 0
  },
  "policy": {
    "kind": "percentage",
    "max_error_pct": 10.0
  },
  "request": {
    "enabled_rule_ids": [
      "GX.1.1",
      "GX.2.5"
    ],
    "inputs": [
      "tests/fixtures/sources/sample_package.xpz"
    ],
    "policy": {
      "kind": "percentage",
      "max_error_pct": 10.0
    },
    "record_history": false,
    "schema_version": 1
  },
  "scanned_files": 1,
  "schema_version": 1,
  "session_id": 1,
  "verdict": "reject"
};

export const findingsPageSample: FindingsPage = {
  "filtered_total": 1,
  "items": [
    {
      "description": "Mala práctica de mantenibilidad: valor en código duro.",
      "file_path": "tests/fixtures/sources/sample_package.xpz",
      "line_content": "where CustomerType = \"VIP\"",
      "line_number": 63,
      "object": {
        "container_path": "tests/fixtures/sources/sample_package.xpz",
        "id": "ProcMalo",
        "member": "PkgDemo/ProcMalo.xml",
        "object_type": "Procedure",
        "package": "PkgDemo"
      },
      "rule_id": "GX.2.5",
      "severity": "ERROR"
    }
  ],
  "limit": 100,
  "offset": 0,
  "rules": [
    "GX.2.5"
  ],
  "session_id": 1,
  "total": 1
};

export const objectWindowSample: ObjectWindow = {
  "cached": false,
  "code_start_line": 4,
  "container_path": "tests/fixtures/sources/sample_package.xpz",
  "id": "ProcMalo",
  "lines": [
    {
      "member_line": 4,
      "text": "",
      "text_line": 1
    },
    {
      "member_line": 5,
      "text": "&MiVar = 1",
      "text_line": 2
    },
    {
      "member_line": 6,
      "text": "sub 'Inicializar'",
      "text_line": 3
    }
  ],
  "member": "PkgDemo/ProcMalo.xml",
  "object_type": "Procedure",
  "package": "PkgDemo",
  "segments": [
    {
      "kind": "Events",
      "member_start_line": 4,
      "text_start_line": 1
    }
  ],
  "session_id": 1,
  "source_modified": false,
  "total_lines": 8,
  "window_end": 3,
  "window_start": 1
};

export const historyPageSample: HistoryIssuesPage = {
  "items": [
    {
      "description": "Mala práctica de mantenibilidad: valor en código duro.",
      "file_path": "tests/fixtures/sources/sample_package.xpz",
      "line_content": "where CustomerType = \"VIP\"",
      "line_number": 63,
      "object": {
        "container_path": "tests/fixtures/sources/sample_package.xpz",
        "id": "ProcMalo",
        "member": "PkgDemo/ProcMalo.xml",
        "object_type": "Procedure",
        "package": "PkgDemo"
      },
      "rule_id": "GX.2.5",
      "severity": "ERROR"
    }
  ],
  "next_cursor": "0:7",
  "run_id": 1
};

