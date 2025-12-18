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

pub struct PythonFile {
    pub file_path: PathBuf,
    pub content: String,
    pub zip_path: Option<PathBuf>,
}

impl PythonFile {
    pub fn full_path(&self) -> String {
        match &self.zip_path {
            Some(zp) => format!("{}:{}", self.file_path.display(), zp.display()),
            None => self.file_path.display().to_string(),
        }
    }
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
    type Item = PythonFile;

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
                    self.matched_count += 1;
                    return Some(PythonFile {
                        file_path: path_in_zip,
                        content,
                        zip_path: Some(self.zip_path.clone()),
                    });
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
    FileSystem(std::iter::Once<PythonFile>),
    Zip(ZipIterator),
    Empty,
}

impl Iterator for EntryIterator {
    type Item = PythonFile;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntryIterator::FileSystem(it) => it.next(),
            EntryIterator::Zip(it) => it.next(),
            EntryIterator::Empty => None,
        }
    }
}

pub fn list_python_files(path: &Path) -> impl Iterator<Item = PythonFile> {
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .flat_map(|entry| {
            let entry_path = entry.path();
            if entry_path.is_file() {
                if is_python_file(entry_path) {
                    if let Ok(content) = fs::read_to_string(entry_path) {
                        return EntryIterator::FileSystem(std::iter::once(PythonFile {
                            file_path: entry_path.to_owned(),
                            content,
                            zip_path: None,
                        }));
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

pub fn dump_package(path: &Path) -> Result<(), std::io::Error> {
    for file in list_python_files(path) {
        if file.zip_path.is_some() {
            println!("--- File: {:?} ---", file.file_path);
            println!("{}", file.content);
            println!("-----------------------");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use crate::list_python_files;
    use std::fs;
    use std::io::Write;
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

        let results: Vec<_> = list_python_files(dir.path()).collect();

        assert_eq!(results.len(), 2);

        let mut found_py = false;
        let mut found_zip_py = false;

        for file in results {
            if file.file_path.ends_with("test.py") {
                assert_eq!(file.content, "print('hello')");
                assert!(file.zip_path.is_none());
                assert_eq!(file.full_path(), py_path.display().to_string());
                found_py = true;
            } else if file.file_path.ends_with("inner.py") && file.zip_path.is_some() {
                assert_eq!(file.content, "print('zip')");
                assert!(file.zip_path.as_ref().unwrap().ends_with("test.zip"));
                assert_eq!(file.full_path(), format!("inner.py:{}", zip_path.display()));
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

        let results: Vec<_> = list_python_files(dir.path()).collect();
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

        let results: Vec<_> = list_python_files(dir.path()).collect();

        assert_eq!(
            results.len(),
            1,
            "Should have found one python file in protected zip"
        );
        assert!(results[0].file_path.ends_with("secret.py"));
        assert!(
            results[0]
                .zip_path
                .as_ref()
                .unwrap()
                .ends_with("protected.zip")
        );
        assert_eq!(results[0].content, "print('infected')");
    }
}
