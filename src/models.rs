use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PortState {
    Open,
    OpenOrFiltered,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostInfo {
    pub ip: IpAddr,
    pub is_up: bool,
}

