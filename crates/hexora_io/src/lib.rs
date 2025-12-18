use log::{debug, error};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ZIP_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const MAX_FILES_IN_ZIP: usize = 1500;

// When a zip is password-protected, we try "infected" as the password.
// This is hardcoded for now, but works for testing purposes.
// The majority of malicious datasets are protected by this password.
// This is almost an industry standard in malware datasets.
const PASSWORD: &[u8] = b"infected";

fn is_python_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("py"))
        .unwrap_or(false)
}

fn is_zip_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("zip"))
        .unwrap_or(false)
}

struct ZipIterator {
    archive: zip::ZipArchive<fs::File>,
    zip_path: PathBuf,
    current_index: usize,
    num_files: usize,
    matched_count: usize,
}

impl ZipIterator {
    fn new(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;

        if metadata.len() > MAX_ZIP_SIZE {
            error!("Zip file {:?} exceeds maximum size of 10MB", path);
            return None;
        }

        let file = fs::File::open(path).ok()?;
        let archive = zip::ZipArchive::new(file).ok()?;
        let num_files = archive.len();

        if num_files > MAX_FILES_IN_ZIP {
            error!(
                "Zip file {:?} exceeds maximum number of files of {}",
                path, MAX_FILES_IN_ZIP
            );
            return None;
        }

        Some(ZipIterator {
            archive,
            zip_path: path.to_owned(),
            current_index: 0,
            num_files,
            matched_count: 0,
        })
    }
}

impl Iterator for ZipIterator {
    type Item = (PathBuf, String);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_index < self.num_files {
            let i = self.current_index;
            self.current_index += 1;

            let mut file = match self.archive.by_index_decrypt(i, PASSWORD) {
                Ok(f) => f,
                Err(_) => continue,
            };

            if !file.is_file() {
                continue;
            }

            let name = file.name().to_string();
            let path_in_zip = PathBuf::from(&name);

            if is_python_file(&path_in_zip) {
                let mut content = String::new();
                if file.read_to_string(&mut content).is_ok() {
                    let full_path = PathBuf::from(format!("{}:{}", self.zip_path.display(), name));
                    self.matched_count += 1;
                    return Some((full_path, content));
                }
            }
        }

        if self.matched_count == 0 {
            debug!("No Python files in zip: {:?}", self.zip_path);
            self.matched_count = 1;
        }

        None
    }
}

enum EntryIterator {
    FileSystem(std::iter::Once<(PathBuf, String)>),
    Zip(ZipIterator),
    Empty,
}

impl Iterator for EntryIterator {
    type Item = (PathBuf, String);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntryIterator::FileSystem(it) => it.next(),
            EntryIterator::Zip(it) => it.next(),
            EntryIterator::Empty => None,
        }
    }
}

pub fn list_python_files(path: &Path) -> impl Iterator<Item = (PathBuf, String)> {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .flat_map(|entry| {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if is_python_file(entry_path) {
                    if let Ok(content) = fs::read_to_string(entry_path) {
                        return EntryIterator::FileSystem(std::iter::once((
                            entry_path.to_owned(),
                            content,
                        )));
                    }
                } else if is_zip_file(entry_path)
                    && let Some(it) = ZipIterator::new(entry_path)
                {
                    return EntryIterator::Zip(it);
                }
            }
            EntryIterator::Empty
        })
}

#[cfg(test)]
mod tests {

    use crate::list_python_files;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;

    #[test]
    fn test_list_python_files() {
        let dir = tempdir().unwrap();

        let py_path = dir.path().join("test.py");
        fs::write(&py_path, "print('hello')").unwrap();

        let zip_path = dir.path().join("test.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.start_file("inner.py", options).unwrap();
        zip.write_all(b"print('zip')").unwrap();
        zip.finish().unwrap();

        let txt_path = dir.path().join("test.txt");
        fs::write(&txt_path, "ignore me").unwrap();

        let results: Vec<(PathBuf, String)> = list_python_files(dir.path()).collect();

        assert_eq!(results.len(), 2);

        let mut found_py = false;
        let mut found_zip_py = false;

        for (path, content) in results {
            if path.ends_with("test.py") {
                assert_eq!(content, "print('hello')");
                found_py = true;
            } else if path.to_str().unwrap().contains("test.zip:inner.py") {
                assert_eq!(content, "print('zip')");
                found_zip_py = true;
            }
        }

        assert!(found_py);
        assert!(found_zip_py);
    }

    #[test]
    fn test_no_python_files_in_zip() {
        let dir = tempdir().unwrap();

        let zip_path = dir.path().join("empty.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();

        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"not a python file").unwrap();
        zip.finish().unwrap();

        let results: Vec<(PathBuf, String)> = list_python_files(dir.path()).collect();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_password_protected_zip() {
        let dir = tempdir().unwrap();
        let zip_path = dir.path().join("protected.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options =
            SimpleFileOptions::default().with_aes_encryption(zip::AesMode::Aes256, "infected");

        zip.start_file("secret.py", options).unwrap();
        zip.write_all(b"print('infected')").unwrap();
        zip.finish().unwrap();

        let results: Vec<(PathBuf, String)> = list_python_files(dir.path()).collect();

        assert_eq!(
            results.len(),
            1,
            "Should have found one python file in protected zip"
        );
        assert!(
            results[0]
                .0
                .to_str()
                .unwrap()
                .contains("protected.zip:secret.py")
        );
        assert_eq!(results[0].1, "print('infected')");
    }
}
