#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistryPolicy {
    pub no_access: Vec<String>,
    pub read_only: Vec<String>,
    pub exact_read_only: Vec<String>,
    pub inherit_user: Vec<String>,
    pub read_write: Vec<String>,
}
