use crate::{PythonFile, is_python_file};
use log::{debug, error};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_ARCHIVE_SIZE: u64 = 50 * 1024 * 1024; // 50MB
const MAX_FILES_IN_ARCHIVE: usize = 2500;

// When a zip is password-protected, we try "infected" as the password.
// This is hardcoded for now, but works for testing purposes.
// The majority of malicious datasets are protected by this password.
// This is almost an industry standard in malware datasets.
const PASSWORD: &[u8] = b"infected";

pub struct TarGzIterator {
    archive_path: PathBuf,
    matched_count: usize,
    files: std::vec::IntoIter<PythonFile>,
}

impl TarGzIterator {
    pub fn new(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;

        if metadata.len() > MAX_ARCHIVE_SIZE {
            error!("tar.gz file {:?} exceeds maximum size of 50MB", path);
            return None;
        }

        let file = fs::File::open(path).ok()?;
        let tar_gz = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(tar_gz);

        let mut python_files = Vec::new();
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                error!("Failed to read entries from {:?}: {}", path, e);
                return None;
            }
        };

        let mut count = 0;
        for entry in entries {
            count += 1;
            if count > MAX_FILES_IN_ARCHIVE {
                error!(
                    "tar.gz file {:?} exceeds maximum number of files of {}",
                    path, MAX_FILES_IN_ARCHIVE
                );
                return None;
            }

            let mut entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    error!("Failed to read entry from {:?}: {}", path, e);
                    continue;
                }
            };
            let path_in_tar = entry.path().ok()?.to_path_buf();

            if is_python_file(&path_in_tar) {
                let mut content = String::new();
                if entry.read_to_string(&mut content).is_ok() {
                    python_files.push(PythonFile {
                        file_path: path_in_tar,
                        content,
                        archive_path: Some(path.to_owned()),
                    });
                }
            }
        }

        Some(TarGzIterator {
            archive_path: path.to_owned(),
            matched_count: 0,
            files: python_files.into_iter(),
        })
    }
}

impl Iterator for TarGzIterator {
    type Item = PythonFile;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(file) = self.files.next() {
            self.matched_count += 1;
            return Some(file);
        }

        if self.matched_count == 0 {
            debug!("No Python files in tar.gz: {:?}", self.archive_path);
            self.matched_count = 1;
        }

        None
    }
}

pub struct ZipIterator {
    archive: zip::ZipArchive<fs::File>,
    archive_path: PathBuf,
    current_index: usize,
    num_files: usize,
    matched_count: usize,
}

impl ZipIterator {
    pub fn new(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;

        if metadata.len() > MAX_ARCHIVE_SIZE {
            error!("Zip file {:?} exceeds maximum size of 50MB", path);
            return None;
        }

        let file = fs::File::open(path).ok()?;
        let archive = zip::ZipArchive::new(file).ok()?;
        let num_files = archive.len();

        if num_files > MAX_FILES_IN_ARCHIVE {
            error!(
                "Zip file {:?} exceeds maximum number of files of {}",
                path, MAX_FILES_IN_ARCHIVE
            );
            return None;
        }

        Some(ZipIterator {
            archive,
            archive_path: path.to_owned(),
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
                        archive_path: Some(self.archive_path.clone()),
                    });
                }
            }
        }

        if self.matched_count == 0 {
            debug!("No Python files in zip: {:?}", self.archive_path);
            self.matched_count = 1;
        }

        None
    }
}
