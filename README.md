# RustScan Lite

A fast, asynchronous network scanner written in Rust. It's designed to be a lightweight alternative to Nmap for quick host discovery and port scanning.

## Features

- **Multi-Phased Scanning**:
  - **Phase 1: Host Discovery**: Automatically filters for live hosts using a fast multi-port TCP ping.
  - **Phase 2: Port Scanning**: Performs concurrent TCP Connect and UDP scans on identified live hosts.
- **Service Detection**: Attempts to grab banners and identify service versions (e.g., SSH, HTTP).
- **Asynchronous Execution**: Powered by `tokio` for high-concurrency scanning.
- **Modern UI**: Real-time color-coded progress bars for different scan phases.
- **Modular Design**: Clean separation between core scanning logic, parsing, and models.

## Installation

### Prerequisites

- **Rust**: [Install Rust](https://rustup.rs/)
- **C++ Build Tools**: Required on Windows for compilation.
  - Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and select the **"Desktop development with C++"** workload.

### Build from Source

```powershell
git clone <your-repo-url>
cd veloscan
cargo build --release
```

The executable will be generated at `target/release/veloscan.exe`.

## Usage

```text
Usage: veloscan.exe [OPTIONS] <TARGETS>

Arguments:
  <TARGETS>  Target IPs or CIDR blocks (e.g., 192.168.1.1, 10.0.0.0/24)

Options:
  -p, --ports <PORTS>          Ports to scan, e.g. 22,80,443 or 1-1000 [default: 1-1024]
  -c, --concurrency <CONCURRENCY>  Concurrent connections limit [default: 1000]
  -t, --timeout <TIMEOUT>      Connection timeout in milliseconds [default: 500]
  -s, --service                Attempt to determine the service version (Banner Grabbing)
  -u, --udp                    Perform UDP scan
  -n, --ping-only              Host discovery only (No port scan)
  -h, --help                   Print help
  -V, --version                Print version
```

### Examples

#### 1. Basic TCP Scan
```powershell
veloscan.exe 192.168.1.1
```

#### 2. Scan specific ports with Service Detection
```powershell
veloscan.exe 192.168.1.1 -p 22,80,443,3389 --service
```

#### 3. UDP Scan + TCP Scan
```powershell
veloscan.exe 192.168.1.1 --udp
```

#### 4. Host Discovery Only (Ping Sweep)
```powershell
veloscan.exe 192.168.1.0/24 --ping-only
```

#### 5. High-Speed Scan
```powershell
veloscan.exe 10.0.0.0/16 -c 5000 -t 200
```

## License

MIT

