use std::net::IpAddr;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum NetworkPolicy {
    #[default]
    Unrestricted,
    Denied,
    AllowList(NetworkAllowList),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkAllowList {
    pub domains: Vec<String>,
    pub addresses: Vec<IpAddr>,
    pub ports: Vec<u16>,
}
