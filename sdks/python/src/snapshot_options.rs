//! Python bindings for snapshot, export, and clone options.

use boxlite::{CloneOptions, ExportOptions, SnapshotOptions};
use pyo3::prelude::*;

use crate::options::PySecret;

/// Options for creating a snapshot (forward-compatible placeholder).
#[pyclass(name = "SnapshotOptions")]
#[derive(Clone)]
pub(crate) struct PySnapshotOptions {}

#[pymethods]
impl PySnapshotOptions {
    #[new]
    fn new() -> Self {
        Self {}
    }
}

impl From<PySnapshotOptions> for SnapshotOptions {
    fn from(_py: PySnapshotOptions) -> Self {
        SnapshotOptions {}
    }
}

/// Options for exporting a box (forward-compatible placeholder).
#[pyclass(name = "ExportOptions")]
#[derive(Clone)]
pub(crate) struct PyExportOptions {}

#[pymethods]
impl PyExportOptions {
    #[new]
    fn new() -> Self {
        Self {}
    }
}

impl From<PyExportOptions> for ExportOptions {
    fn from(_py: PyExportOptions) -> Self {
        ExportOptions {}
    }
}

/// Options for cloning a box.
///
/// ``secrets`` gives the clone its own secret **values** while keeping the
/// source box's secret names. A clone reuses the source box's container image
/// config, so its guest keeps the source's ``BOXLITE_SECRET_*`` placeholder
/// environment; only the host-side substitution table is rebuilt per start.
/// The list must therefore name exactly the source box's secrets, each with the
/// same ``hosts`` and the same ``placeholder`` — only ``value`` may differ.
/// Anything else is rejected when the clone runs, rather than producing a box
/// that looks configured and authenticates as nobody. Omit ``secrets`` to
/// inherit the source box's unchanged.
///
/// Example::
///
///     from boxlite import CloneOptions, Secret
///
///     worker = await box.clone_box(
///         options=CloneOptions(
///             secrets=[
///                 Secret(name="gh", value="fake-token-123",
///                        hosts=["api.github.com"]),
///             ],
///         ),
///     )
///
/// ``env`` and ``network`` are not offered here yet; see ``CloneOptions`` in the
/// Rust core for why ``env`` cannot be honoured by a clone today.
#[pyclass(name = "CloneOptions")]
#[derive(Clone)]
pub(crate) struct PyCloneOptions {
    /// New values for the source box's secrets, or ``None`` to inherit them.
    #[pyo3(get, set)]
    pub(crate) secrets: Option<Vec<PySecret>>,
}

#[pymethods]
impl PyCloneOptions {
    #[new]
    #[pyo3(signature = (*, secrets=None))]
    fn new(secrets: Option<Vec<PySecret>>) -> Self {
        Self { secrets }
    }

    fn __repr__(&self) -> String {
        match &self.secrets {
            None => "CloneOptions(secrets=None)".to_string(),
            Some(secrets) => format!(
                "CloneOptions(secrets=[{}])",
                secrets
                    .iter()
                    .map(|s| format!("Secret(name={:?}, value=[REDACTED])", s.name))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

impl From<PyCloneOptions> for CloneOptions {
    fn from(py: PyCloneOptions) -> Self {
        CloneOptions {
            secrets: py
                .secrets
                .map(|secrets| secrets.into_iter().map(PySecret::into_core).collect()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py_secret(name: &str, value: &str, hosts: &[&str]) -> PySecret {
        PySecret {
            name: name.to_string(),
            value: value.to_string(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            placeholder: None,
        }
    }

    #[test]
    fn clone_options_default_inherits_source_secrets() {
        let opts: CloneOptions = PyCloneOptions { secrets: None }.into();
        assert!(
            opts.secrets.is_none(),
            "CloneOptions() must leave the source box's secrets alone"
        );
    }

    #[test]
    fn clone_options_secrets_convert_to_core_secrets() {
        let py = PyCloneOptions {
            secrets: Some(vec![py_secret("t", "clone-value", &["httpbin.org"])]),
        };
        let opts: CloneOptions = py.into();
        let secrets = opts.secrets.expect("secrets should be carried through");
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].name, "t");
        assert_eq!(secrets[0].value, "clone-value");
        assert_eq!(secrets[0].hosts, vec!["httpbin.org".to_string()]);
        assert_eq!(
            secrets[0].placeholder, "<BOXLITE_SECRET:t>",
            "an unset placeholder must default the same way BoxOptions does, \
             so the clone matches the source box's baked env"
        );
    }

    #[test]
    fn clone_options_secrets_keep_an_explicit_placeholder() {
        let mut secret = py_secret("t", "clone-value", &["httpbin.org"]);
        secret.placeholder = Some("<MY_TOKEN>".to_string());
        let opts: CloneOptions = PyCloneOptions {
            secrets: Some(vec![secret]),
        }
        .into();
        assert_eq!(opts.secrets.unwrap()[0].placeholder, "<MY_TOKEN>");
    }

    #[test]
    fn clone_options_repr_redacts_secret_values() {
        let repr = PyCloneOptions {
            secrets: Some(vec![py_secret("t", "clone-value", &["httpbin.org"])]),
        }
        .__repr__();
        assert!(!repr.contains("clone-value"), "repr must not leak a value");
        assert!(repr.contains("[REDACTED]"));
        assert!(repr.contains("\"t\""));
    }
}
