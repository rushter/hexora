mod archive;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use archive::{TarGzIterator, ZipIterator};

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

pub(crate) fn is_python_file(path: &Path) -> bool {
    has_extension(path, "py")
}

fn is_zip_file(path: &Path) -> bool {
    has_extension(path, "zip")
}

fn is_tar_gz_file(path: &Path) -> bool {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    filename.to_lowercase().ends_with(".tar.gz")
}

pub enum EntryIterator {
    FileSystem(std::iter::Once<PythonFile>),
    Zip(ZipIterator),
    TarGz(TarGzIterator),
    Empty,
}

impl Iterator for EntryIterator {
    type Item = PythonFile;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EntryIterator::FileSystem(it) => it.next(),
            EntryIterator::Zip(it) => it.next(),
            EntryIterator::TarGz(it) => it.next(),
            EntryIterator::Empty => None,
        }
    }
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

pub fn read_exclude_names(path: &Path) -> Result<HashSet<String>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

pub fn list_python_files(
    path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> impl Iterator<Item = PythonFile> {
    let exclude_names = exclude_names.cloned().unwrap_or_default();
    walkdir::WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .flat_map(move |entry| {
            let path = entry.path();

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if exclude_names.contains(name) {
                    return EntryIterator::Empty;
                }
            }

            if is_python_file(path) {
                if let Ok(content) = fs::read_to_string(path) {
                    return EntryIterator::FileSystem(std::iter::once(PythonFile {
                        file_path: path.to_owned(),
                        content,
                        zip_path: None,
                    }));
                }
            }

            if is_zip_file(path) {
                if let Some(it) = ZipIterator::new(path) {
                    return EntryIterator::Zip(it);
                }
            }

            if is_tar_gz_file(path) {
                if let Some(it) = TarGzIterator::new(path) {
                    return EntryIterator::TarGz(it);
                }
            }

            EntryIterator::Empty
        })
}

pub fn dump_package(path: &Path, filter: Option<&str>) -> Result<(), std::io::Error> {
    let path_filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    println!("=== Dumping package: {} ===", path_filename);
    for file in list_python_files(path, None) {
        if file.zip_path.is_some() {
            if let Some(f) = filter {
                if !file.file_path.to_string_lossy().contains(f) {
                    continue;
                }
            }
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
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::collections::HashSet;
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

        let results: Vec<_> = list_python_files(dir.path(), None).collect();

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
    fn test_list_python_files_with_exclude() {
        let dir = tempdir().unwrap();

        let py_path1 = dir.path().join("test1.py");
        fs::write(&py_path1, "print('hello 1')").unwrap();

        let py_path2 = dir.path().join("test2.py");
        fs::write(&py_path2, "print('hello 2')").unwrap();

        let zip_path = dir.path().join("test.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.start_file("inner.py", options).unwrap();
        zip.write_all(b"print('zip')").unwrap();
        zip.finish().unwrap();

        let mut exclude = HashSet::new();
        exclude.insert("test1.py".to_string());
        exclude.insert("test.zip".to_string());

        let results: Vec<_> = list_python_files(dir.path(), Some(&exclude)).collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file_path.file_name().unwrap(), "test2.py");
    }

    #[test]
    fn test_list_python_files_tar_gz() {
        let dir = tempdir().unwrap();

        let tar_gz_path = dir.path().join("test.tar.gz");
        {
            let file = fs::File::create(&tar_gz_path).unwrap();
            let enc = GzEncoder::new(file, Compression::default());
            let mut tar = tar::Builder::new(enc);

            let mut header = tar::Header::new_gnu();
            let content = b"print('tar.gz')";
            header.set_size(content.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, "inner.py", &content[..])
                .unwrap();
            tar.finish().unwrap();
        }

        let results: Vec<_> = list_python_files(dir.path(), None).collect();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "print('tar.gz')");
        assert!(
            results[0]
                .zip_path
                .as_ref()
                .unwrap()
                .ends_with("test.tar.gz")
        );
        assert_eq!(results[0].file_path, std::path::Path::new("inner.py"));
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

        let results: Vec<_> = list_python_files(dir.path(), None).collect();
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

        let results: Vec<_> = list_python_files(dir.path(), None).collect();

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

    #[test]
    fn test_read_exclude_names() {
        let dir = tempdir().unwrap();
        let exclude_path = dir.path().join("exclude.txt");
        fs::write(
            &exclude_path,
            "file1.py\n  file2.py  \n\n# comment\n  # another comment\nfile3.py",
        )
        .unwrap();

        let exclude = crate::read_exclude_names(&exclude_path).unwrap();
        assert_eq!(exclude.len(), 3);
        assert!(exclude.contains("file1.py"));
        assert!(exclude.contains("file2.py"));
        assert!(exclude.contains("file3.py"));
        assert!(!exclude.contains("# comment"));
    }
}
