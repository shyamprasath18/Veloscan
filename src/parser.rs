use ipnet::IpNet;
use std::collections::BTreeSet;
use std::error::Error;
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;

pub fn parse_targets(targets: &str) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    let mut ips = BTreeSet::new();
    for target in targets.split(',') {
        let target = target.trim();
        if target.is_empty() {
            continue;
        }

        if let Ok(net) = IpNet::from_str(target) {
            if net.prefix_len() == 32 || (net.addr().is_ipv6() && net.prefix_len() == 128) {
                ips.insert(net.addr());
            } else {
                let mut added_any = false;
                for ip in net.hosts() {
                    ips.insert(ip);
                    added_any = true;
                }
                if !added_any {
                    ips.insert(net.addr());
                }
            }
        } else if let Ok(ip) = IpAddr::from_str(target) {
            ips.insert(ip);
        } else {
            // Hostname fallback
            let addrs = format!("{}:0", target).to_socket_addrs()?;
            for addr in addrs {
                ips.insert(addr.ip());
            }
        }
    }
    Ok(ips.into_iter().collect())
}

pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, Box<dyn Error>> {
    let mut ports = Vec::new();

    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }

        if let Some((start, end)) = item.split_once('-') {
            let start: u16 = start.trim().parse()?;
            let end: u16 = end.trim().parse()?;

            if start > end {
                return Err(format!("invalid port range: {item}").into());
            }

            for port in start..=end {
                ports.push(port);
            }
        } else {
            ports.push(item.parse()?);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_targets() {
        let ips = parse_targets("192.168.1.1").unwrap();
        assert_eq!(ips.len(), 1);

        let ips = parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(ips.len(), 2);

        let ips = parse_targets("192.168.1.1/32").unwrap();
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_parse_ports() {
        let ports = parse_port_spec("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }
}
