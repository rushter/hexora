use std::path::{Path, PathBuf};

fn list_files_in_dir(path: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| {
                    let ext = ext.to_ascii_lowercase();
                    ext == "py"
                })
                .unwrap_or(false)
        })
        .map(|e| e.path().to_owned())
        .collect();
    files.sort();
    files
}

pub fn list_python_files(path: &Path) -> Option<Vec<PathBuf>> {
    if path.is_file() {
        Some(Vec::from([path.to_path_buf()]))
    } else if path.is_dir() {
        Some(list_files_in_dir(path))
    } else {
        None
    }
}
