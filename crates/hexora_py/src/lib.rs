/// This module provides a Python interface to hexora library.
///
use hexora::cli;
use std::path::PathBuf;

use hexora::audit::parse;
use hexora::audit::result::AuditItem;
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
                let res = AuditResult {
                    items: r.items,
                    path: r.path,
                    archive_path: r.archive_path,
                };
                let obj = pythonize(py, &res).map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to serialize result: {}", e))
                })?;
                items.push(obj.extract().map_err(|e| {
                    PyRuntimeError::new_err(format!("Failed to extract Python object: {}", e))
                })?);
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
    let result = parse::audit_file(&input_path);
    match result {
        Ok(res) => Python::attach(|py| {
            let res = AuditResult {
                items: res.items,
                path: res.path,
                archive_path: res.archive_path,
            };
            let obj = pythonize(py, &res).map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to serialize result: {}", e))
            })?;
            obj.extract().map_err(|e| {
                PyRuntimeError::new_err(format!("Failed to extract Python object: {}", e))
            })
        }),
        Err(e) => Err(PyRuntimeError::new_err(format!("Audit failed: {}", e))),
    }
}

#[pymodule]
fn _hexora(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(audit_path, m)?)?;
    m.add_function(wrap_pyfunction!(audit_file, m)?)?;
    m.add_function(wrap_pyfunction!(run_cli, m)?)?;
    Ok(())
}
