mod models;
mod parser;
mod scanner;

const TOP_100_PORTS: &[u16] = &[20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080];

use crate::models::{Protocol, ScanResult};
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use tokio::sync::mpsc;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Parser)]
#[command(
    name = "veloscan",
    version,
    about = "Fast asynchronous network scanner",
    long_about = "A Rust-based alternative to Nmap for quick host and port discovery."
)]
struct Args {
    #[arg(help = "Target IPs or CIDR blocks (e.g., 192.168.1.1, 10.0.0.0/24)")]
    targets: String,

    #[arg(
        short,
        long,
        default_value = "1-1024",
        help = "Ports to scan, e.g. 22,80,443 or 1-1000"
    )]
    ports: String,

    #[arg(
        short,
        long,
        default_value_t = 1000,
        help = "Concurrent connections limit"
    )]
    concurrency: usize,

    #[arg(
        short = 't',
        long,
        default_value_t = 500,
        help = "Connection timeout in milliseconds"
    )]
    timeout: u64,

    #[arg(
        short = 's',
        long = "service",
        help = "Attempt to determine the service version (Banner Grabbing)"
    )]
    service_detection: bool,

    #[arg(short = 'u', long = "udp", help = "Perform UDP scan")]
    udp: bool,

    #[arg(short = 'n', long = "ping-only", help = "Host discovery only (No port scan)")]    #[arg(short = 'n', long = "ping-only", help = "Host discovery only (No port scan)")]
    ping_only: bool,

    #[arg(long, help = "Output results to a JSON file")]
    json: Option<String>,

    #[arg(long, help = "Scan top N most common ports (e.g., 100, 1000)")]
    top_ports: Option<usize>,

    #[arg(long, help = "Targets to exclude from the scan")]
    exclude: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

        let mut ips = parser::parse_targets(&args.targets)?;
    if let Some(exclude) = &args.exclude {
        let excluded_ips = parser::parse_targets(exclude)?;
        ips.retain(|ip| !excluded_ips.contains(ip));
    }
    if ips.is_empty() {
        return Err("No valid targets provided".into());
    }

        let ports = if let Some(n) = args.top_ports {
        TOP_100_PORTS.iter().take(n).copied().collect()
    } else {
        parser::parse_port_spec(&args.ports)?
    };

    print_header(&args);

    // 1. Host Discovery
    println!("{}", "Phase 1: Host Discovery".bold().blue());
    let live_hosts = perform_host_discovery(&ips, &args).await?;
    println!("Found {} live hosts.", live_hosts.len().to_string().green().bold());
    
    if args.ping_only {
        print_host_discovery_results(&live_hosts);
        return Ok(());
    }

    if live_hosts.is_empty() {
        println!("{}", "No live hosts found. Exiting.".yellow());
        return Ok(());
    }

    // 2. Port Scanning
    println!("\n{}", "Phase 2: Port Scanning".bold().blue());
    let mut scan_results = Vec::new();

    // TCP Scan
    if !args.udp || (args.udp && !ports.is_empty()) {
        println!("Running TCP Connect scan...");
        scan_results.extend(perform_tcp_scan(&live_hosts, &ports, &args).await?);
    }

    // UDP Scan
    if args.udp {
        println!("Running UDP scan...");
        scan_results.extend(perform_udp_scan(&live_hosts, &ports, &args).await?);
    }

    print_scan_results(&live_hosts, scan_results.clone());
    if let Some(json_path) = &args.json {
        let json_data = serde_json::to_string_pretty(&scan_results)?;
        let mut file = File::create(json_path)?;
        file.write_all(json_data.as_bytes())?;
        println!("\nResults saved to {}", json_path.cyan());
    }

    Ok(())
}

fn print_header(args: &Args) {
    println!(
        "{}",
        "\n╔══════════════════════════════════════════════════════╗"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "║  RustScan Lite  -  Fast Async Network Scanner        ║"
            .bold()
            .cyan()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════╝"
            .bold()
            .cyan()
    );

    println!("Targets       : {}", args.targets.bright_white());
    if args.top_ports.is_some() { println!("Ports         : {}", format!("Top {}", args.top_ports.unwrap()).bright_white()); } else { println!("Ports         : {}", args.ports.bright_white()); }
    println!(
        "Scan Type     : {}{}",
        if args.ping_only { "Ping only".yellow() } else { "TCP Connect".green() },
        if args.udp { " + UDP".magenta() } else { " ".normal() }
    );
    println!(
        "Concurrency   : {}",
        args.concurrency.to_string().bright_white()
    );
    println!(
        "Timeout       : {} ms\n",
        args.timeout.to_string().bright_white()
    );
}

async fn perform_host_discovery(ips: &[IpAddr], args: &Args) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    let pb = ProgressBar::new(ips.len() as u64);
    pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] {bar:40.blue} {pos}/{len} hosts checked")?);
    
    let (tx, mut rx) = mpsc::channel(1000);
    let (p_tx, mut p_rx) = mpsc::channel(1000);

    let pb_clone = pb.clone();
    tokio::spawn(async move {
        while p_rx.recv().await.is_some() {
            pb_clone.inc(1);
        }
    });

    let ips_vec = ips.to_vec();
    let concurrency = args.concurrency;
    let timeout = args.timeout;

    tokio::spawn(async move {
        scanner::host_discovery(ips_vec, concurrency, timeout, tx, p_tx).await;
    });

    let mut live_hosts = Vec::new();
    while let Some(host) = rx.recv().await {
        if host.is_up {
            live_hosts.push(host.ip);
        }
    }
    pb.finish_and_clear();
    Ok(live_hosts)
}

async fn perform_tcp_scan(hosts: &[IpAddr], ports: &[u16], args: &Args) -> Result<Vec<ScanResult>, Box<dyn Error>> {
    let total = (hosts.len() * ports.len()) as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] {bar:40.green} {pos}/{len} TCP ports")?);
    
    let (tx, mut rx) = mpsc::channel(10000);
    let (p_tx, mut p_rx) = mpsc::channel(10000);

    let pb_clone = pb.clone();
    tokio::spawn(async move {
        while p_rx.recv().await.is_some() {
            pb_clone.inc(1);
        }
    });

    let hosts_vec = hosts.to_vec();
    let ports_vec = ports.to_vec();
    let concurrency = args.concurrency;
    let timeout = args.timeout;
    let service_detection = args.service_detection;

    tokio::spawn(async move {
        scanner::tcp_scan(hosts_vec, ports_vec, concurrency, timeout, service_detection, tx, p_tx).await;
    });

    let mut results = Vec::new();
    while let Some(res) = rx.recv().await {
        results.push(res);
    }
    pb.finish_and_clear();
    Ok(results)
}

async fn perform_udp_scan(hosts: &[IpAddr], ports: &[u16], args: &Args) -> Result<Vec<ScanResult>, Box<dyn Error>> {
    let total = (hosts.len() * ports.len()) as u64;
    let pb = ProgressBar::new(total);
    pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] {bar:40.magenta} {pos}/{len} UDP ports")?);
    
    let (tx, mut rx) = mpsc::channel(10000);
    let (p_tx, mut p_rx) = mpsc::channel(10000);

    let pb_clone = pb.clone();
    tokio::spawn(async move {
        while p_rx.recv().await.is_some() {
            pb_clone.inc(1);
        }
    });

    let hosts_vec = hosts.to_vec();
    let ports_vec = ports.to_vec();
    let concurrency = args.concurrency;
    let timeout = args.timeout;

    tokio::spawn(async move {
        scanner::udp_scan(hosts_vec, ports_vec, concurrency, timeout, tx, p_tx).await;
    });

    let mut results = Vec::new();
    while let Some(res) = rx.recv().await {
        results.push(res);
    }
    pb.finish_and_clear();
    Ok(results)
}

fn print_host_discovery_results(live_hosts: &[IpAddr]) {
    println!("\n{}", "Host discovery results:".bold().green());
    for ip in live_hosts {
        println!("Host {} is {}", ip.to_string().bright_white(), "UP".green().bold());
    }
    println!("\nTotal live hosts: {}", live_hosts.len());
}

fn print_scan_results(live_hosts: &[IpAddr], results: Vec<ScanResult>) {
    let mut results_map: HashMap<IpAddr, Vec<ScanResult>> = HashMap::new();
    for res in results {
        results_map.entry(res.ip).or_default().push(res);
    }

    println!("\n{}", "Scan summary".bold().green());
    for ip in live_hosts {
        println!("\nHost: {}", ip.to_string().bright_white());
        if let Some(mut host_results) = results_map.remove(ip) {
            host_results.sort_by_key(|r| r.port);
            for res in host_results {
                let proto = match res.protocol {
                    Protocol::Tcp => "tcp".cyan(),
                    Protocol::Udp => "udp".magenta(),
                };
                let state = match res.state {
                    crate::models::PortState::Open => "OPEN".green().bold(),
                    crate::models::PortState::OpenOrFiltered => "OPEN|FILTERED".yellow().bold(),
                };
                let banner = res.banner.map(|b| format!(" [{}]", b.dimmed())).unwrap_or_default();
                
                println!("  {} {}/{}{}", state, res.port.to_string().bright_white(), proto, banner);
            }
        } else {
            println!("  No open ports found");
        }
    }
}





