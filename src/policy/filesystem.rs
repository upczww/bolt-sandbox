use std::path::PathBuf;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FilesystemPolicy {
    pub read_write: Vec<PathBuf>,
    pub read_only: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
    pub metadata_read: Vec<PathBuf>,
    pub inherit_user: Vec<PathBuf>,
}
