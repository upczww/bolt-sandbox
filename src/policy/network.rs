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
    pub addresses: Vec<IpCidr>,
    pub ports: Vec<PortRange>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IpCidr {
    pub address: IpAddr,
    pub prefix_length: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}
