use crate::models::{HostInfo, PortState, Protocol, ScanResult};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

pub async fn host_discovery(
    ips: Vec<IpAddr>,
    concurrency: usize,
    timeout_ms: u64,
    result_tx: mpsc::Sender<HostInfo>,
    progress_tx: mpsc::Sender<()>,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout_duration = Duration::from_millis(timeout_ms);
    let common_ports = [80, 443, 22, 21, 3389, 135, 445, 139, 5354];

    for ip in ips {
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let tx = result_tx.clone();
        let p_tx = progress_tx.clone();

        tokio::spawn(async move {
            let mut is_up = false;
            for port in common_ports {
                let addr = SocketAddr::new(ip, port);
                if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(&addr)).await {
                    is_up = true;
                    break;
                }
            }
            let _ = tx.send(HostInfo { ip, is_up }).await;
            let _ = p_tx.send(()).await;
            drop(permit);
        });
    }

    let _ = semaphore.acquire_many(concurrency as u32).await.unwrap();
}

pub async fn tcp_scan(
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    concurrency: usize,
    timeout_ms: u64,
    service_detection: bool,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tx: mpsc::Sender<()>,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout_duration = Duration::from_millis(timeout_ms);

    for ip in ips {
        for port in ports.iter().copied() {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            let tx = result_tx.clone();
            let p_tx = progress_tx.clone();

            tokio::spawn(async move {
                let addr = SocketAddr::new(ip, port);
                let stream_result = timeout(timeout_duration, TcpStream::connect(&addr)).await;

                match stream_result {
                    Ok(Ok(mut stream)) => {
                        let mut banner = None;
                        if service_detection {
                            banner = grab_banner(&mut stream, port).await;
                        }
                        let _ = tx.send(ScanResult {
                            ip,
                            port,
                            protocol: Protocol::Tcp,
                            state: PortState::Open,
                            banner,
                        }).await;
                    }
                    _ => {}
                }
                let _ = p_tx.send(()).await;
                drop(permit);
            });
        }
    }

    let _ = semaphore.acquire_many(concurrency as u32).await.unwrap();
}

pub async fn udp_scan(
    ips: Vec<IpAddr>,
    ports: Vec<u16>,
    concurrency: usize,
    timeout_ms: u64,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tx: mpsc::Sender<()>,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let timeout_duration = Duration::from_millis(timeout_ms);

    for ip in ips {
        for port in ports.iter().copied() {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            let tx = result_tx.clone();
            let p_tx = progress_tx.clone();

            tokio::spawn(async move {
                let addr = SocketAddr::new(ip, port);
                let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                
                if let Ok(socket) = UdpSocket::bind(bind_addr).await {
                    if let Ok(_) = socket.connect(&addr).await {
                        // Send an empty packet
                        let _ = socket.send(&[]).await;
                        
                        let mut buf = [0u8; 1];
                        match timeout(timeout_duration, socket.recv(&mut buf)).await {
                            Ok(Ok(_)) => {
                                // Received something back -> Open
                                let _ = tx.send(ScanResult {
                                    ip,
                                    port,
                                    protocol: Protocol::Udp,
                                    state: PortState::Open,
                                    banner: None,
                                }).await;
                            }
                            Ok(Err(_)) => {
                                // Error (e.g. Connection Refused ICMP)
                            }
                            Err(_) => {
                                // Timeout -> Open|Filtered (common for UDP)
                                let _ = tx.send(ScanResult {
                                    ip,
                                    port,
                                    protocol: Protocol::Udp,
                                    state: PortState::OpenOrFiltered,
                                    banner: None,
                                }).await;
                            }
                        }
                    }
                }
                let _ = p_tx.send(()).await;
                drop(permit);
            });
        }
    }

    let _ = semaphore.acquire_many(concurrency as u32).await.unwrap();
}

async fn grab_banner(stream: &mut TcpStream, port: u16) -> Option<String> {
    let mut buffer = [0u8; 1024];
    let read_timeout = Duration::from_millis(1500);

    // Some services send a greeting immediately (SSH, FTP, SMTP)
    if let Ok(Ok(n)) = timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        if n > 0 {
            return Some(sanitize_banner(&buffer[..n]));
        }
    }

    match port {
        80 | 8080 | 443 | 3000 | 5000 | 8000 => {
            let _ = stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await;
            if let Ok(Ok(n)) = timeout(read_timeout, stream.read(&mut buffer)).await {
                if n > 0 {
                    let full_response = String::from_utf8_lossy(&buffer[..n]);
                    if let Some(first_line) = full_response.lines().next() {
                        return Some(first_line.to_string());
                    }
                }
            }
        }
        6379 => {
            let _ = stream.write_all(b"PING\r\n").await;
            if let Ok(Ok(n)) = timeout(read_timeout, stream.read(&mut buffer)).await {
                if n > 0 {
                    let resp = String::from_utf8_lossy(&buffer[..n]);
                    if resp.contains("+PONG") { return Some("Redis".to_string()); }
                }
            }
        }
        3306 => {
            // MySQL usually sends a handshake, but we can try to identify it from a small read
            return Some("MySQL".to_string());
        }
        5432 => {
            // Postgres
            return Some("PostgreSQL".to_string());
        }
        _ => {}
    }

    None
}

fn sanitize_banner(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim()
        .replace(['\n', '\r'], " ")
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
}


