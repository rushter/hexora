/// This module provides a Python interface to hexora library.
///
use hexora::audit::annotate::annotate_result;
use hexora::cli;
use std::path::PathBuf;

use hexora::audit::parse;
use hexora::audit::result::{AuditItem as CoreAuditItem, AuditResult as CoreAuditResult};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pythonize::pythonize;
use serde::Serialize;

const CLI_START_ARG_PYTHON: usize = 1;

#[derive(Debug, Serialize)]
pub struct AuditResult {
    pub items: Vec<AuditItem>,
    pub path: PathBuf,
    pub archive_path: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct AuditItem {
    #[serde(flatten)]
    pub item: CoreAuditItem,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
}

fn is_archive_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.to_ascii_lowercase().ends_with(".tar.gz"))
}

fn map_audit_result(result: CoreAuditResult) -> AuditResult {
    let path = result.path;
    let archive_path = result.archive_path;
    let source_code = result.source_code;

    let items = result
        .items
        .into_iter()
        .map(|item| {
            let annotation =
                annotate_result(&item, &path, archive_path.as_deref(), &source_code, false).ok();

            AuditItem { item, annotation }
        })
        .collect();

    AuditResult {
        items,
        path,
        archive_path,
    }
}

fn to_py_audit_result(py: Python<'_>, result: CoreAuditResult) -> PyResult<Py<PyAny>> {
    let res = map_audit_result(result);
    let obj = pythonize(py, &res)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to serialize result: {}", e)))?;
    obj.extract()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to extract Python object: {}", e)))
}

#[pyfunction]
fn run_cli() -> PyResult<()> {
    cli::run_cli(CLI_START_ARG_PYTHON);
    Ok(())
}

/// Runs audit in the specified folder.
/// --
#[pyfunction]
#[pyo3(signature = (input_path))]
fn audit_path(input_path: PathBuf) -> PyResult<Vec<Py<PyAny>>> {
    let results = parse::audit_path(&input_path, None);
    match results {
        Ok(results) => Python::attach(|py| {
            let mut items = Vec::new();
            for r in results {
                items.push(to_py_audit_result(py, r)?);
            }
            Ok(items)
        }),
        Err(e) => Err(PyRuntimeError::new_err(format!("Audit failed: {}", e))),
    }
}

/// Runs audit for the specified path.
/// --
#[pyfunction]
#[pyo3(signature = (input_path))]
fn audit_file(input_path: PathBuf) -> PyResult<Py<PyAny>> {
    if is_archive_path(&input_path) {
        let results = parse::audit_path(&input_path, None)
            .map_err(|e| PyRuntimeError::new_err(format!("Audit failed: {}", e)))?;

        return Python::attach(|py| {
            let items: Vec<AuditResult> = results.map(map_audit_result).collect();
            pythonize(py, &items)
                .map_err(|e| PyRuntimeError::new_err(format!("Failed to serialize result: {}", e)))?
                .extract()
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to extract Python object: {}", e))
                })
        });
    }

    let result = parse::audit_file(&input_path)
        .map_err(|e| PyRuntimeError::new_err(format!("Audit failed: {}", e)))?;
    Python::attach(|py| to_py_audit_result(py, result))
}

#[pymodule]
fn _hexora(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(audit_path, m)?)?;
    m.add_function(wrap_pyfunction!(audit_file, m)?)?;
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    Ok(())
}
