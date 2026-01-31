use crate::network_map::{Device, PortState, Protocol, ScanPhase, ScanProgress, Service, COMMON_PORTS};
use color_eyre::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const BANNER_TIMEOUT: Duration = Duration::from_millis(1000);
const MAX_CONCURRENT_PORTS: usize = 50;
const MAX_CONCURRENT_DEVICES: usize = 10;

pub async fn scan_devices_ports(
    devices: &mut [Device],
    progress_tx: Option<mpsc::Sender<ScanProgress>>,
) -> Result<()> {
    let devices_count = devices.len();
    let total_ports = COMMON_PORTS.len() * devices_count;
    let mut scanned = 0;

    for chunk in devices.chunks_mut(MAX_CONCURRENT_DEVICES) {
        let mut handles = Vec::new();
        for device in chunk.iter() {
            let ip = device.ip_address.clone();
            let handle = tokio::spawn(async move { scan_device_ports(&ip, COMMON_PORTS).await });
            handles.push((device.mac_address.clone(), handle));
        }

        for (mac, handle) in handles {
            if let Ok(Ok(services)) = handle.await {
                if let Some(device) = chunk.iter_mut().find(|d| d.mac_address == mac) {
                    device.services = services;
                }
            }
            scanned += COMMON_PORTS.len();
            if let Some(ref tx) = progress_tx {
                let _ = tx.send(ScanProgress {
                    phase: ScanPhase::PortScan,
                    devices_found: devices_count,
                    current_device: Some(mac),
                    ports_scanned: scanned,
                    total_ports,
                }).await;
            }
        }
    }
    Ok(())
}

async fn scan_device_ports(ip: &str, ports: &[u16]) -> Result<Vec<Service>> {
    let mut services = Vec::new();
    for chunk in ports.chunks(MAX_CONCURRENT_PORTS) {
        let mut handles = Vec::new();
        for &port in chunk {
            let ip = ip.to_string();
            let handle = tokio::spawn(async move { scan_port(&ip, port).await });
            handles.push((port, handle));
        }
        for (_port, handle) in handles {
            if let Ok(Ok(Some(service))) = handle.await {
                services.push(service);
            }
        }
    }
    Ok(services)
}

async fn scan_port(ip: &str, port: u16) -> Result<Option<Service>> {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse()?;
    let connect_result = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;

    match connect_result {
        Ok(Ok(mut stream)) => {
            let banner = grab_banner(&mut stream, port).await.ok().flatten();
            let service_name = identify_service(port, banner.as_deref());
            let detected_agent = detect_agent(port, banner.as_deref());
            Ok(Some(Service {
                port,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service_name,
                banner,
                detected_agent,
            }))
        }
        Ok(Err(_)) => Ok(None),
        Err(_) => Ok(None),
    }
}

async fn grab_banner(stream: &mut TcpStream, port: u16) -> Result<Option<String>> {
    let mut buf = [0u8; 256];
    let probe = match port {
        80 | 8080 | 8000 | 8001 | 3000 | 3001 | 8008 | 11434 | 18789 | 18793 => {
            Some("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        }
        _ => None,
    };
    if let Some(probe) = probe {
        let _ = stream.write_all(probe.as_bytes()).await;
    }
    match timeout(BANNER_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n])
                .chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .take(200)
                .collect::<String>()
                .trim()
                .to_string();
            if banner.is_empty() { Ok(None) } else { Ok(Some(banner)) }
        }
        _ => Ok(None),
    }
}

fn identify_service(port: u16, banner: Option<&str>) -> Option<String> {
    if let Some(banner) = banner {
        let banner_lower = banner.to_lowercase();
        if banner_lower.contains("ssh") { return Some("SSH".to_string()); }
        if banner_lower.contains("http") || banner_lower.contains("html") { return Some("HTTP".to_string()); }
        if banner_lower.contains("ftp") { return Some("FTP".to_string()); }
        if banner_lower.contains("smtp") { return Some("SMTP".to_string()); }
        if banner_lower.contains("ollama") { return Some("Ollama API".to_string()); }
        if banner_lower.contains("openclaw") { return Some("OpenClaw".to_string()); }
    }
    match port {
        21 => Some("FTP".to_string()),
        22 => Some("SSH".to_string()),
        23 => Some("Telnet".to_string()),
        25 => Some("SMTP".to_string()),
        53 => Some("DNS".to_string()),
        80 => Some("HTTP".to_string()),
        443 => Some("HTTPS".to_string()),
        139 | 445 => Some("SMB".to_string()),
        548 => Some("AFP".to_string()),
        554 => Some("RTSP".to_string()),
        3389 => Some("RDP".to_string()),
        5000 | 5001 => Some("Synology".to_string()),
        8080 | 8443 => Some("HTTP Alt".to_string()),
        9100 => Some("Printer".to_string()),
        62078 => Some("Apple Device".to_string()),
        8008 | 8009 => Some("Chromecast".to_string()),
        11434 => Some("Ollama".to_string()),
        9229 => Some("Node Debug".to_string()),
        8501 => Some("Streamlit".to_string()),
        3000 | 3001 => Some("Dev Server".to_string()),
        8000 | 8001 => Some("Python Server".to_string()),
        18789 => Some("OpenClaw Gateway".to_string()),
        18793 => Some("OpenClaw Canvas".to_string()),
        _ => None,
    }
}

fn detect_agent(port: u16, banner: Option<&str>) -> Option<String> {
    if let Some(banner) = banner {
        let banner_lower = banner.to_lowercase();
        // OpenClaw agents (check first for specific agent names)
        if banner_lower.contains("openclaw") || banner_lower.contains("open-claw") {
            // Try to identify specific bot from banner
            if banner_lower.contains("clawdbot") || banner_lower.contains("clawd") {
                return Some("Clawdbot (OpenClaw)".to_string());
            }
            if banner_lower.contains("moldbot") || banner_lower.contains("mold") {
                return Some("Moldbot (OpenClaw)".to_string());
            }
            return Some("OpenClaw".to_string());
        }
        // Claude-related agents
        if banner_lower.contains("claude") || banner_lower.contains("anthropic") { return Some("Claude Code".to_string()); }
        if banner_lower.contains("clawdbot") || banner_lower.contains("clawd") { return Some("Clawdbot".to_string()); }
        if banner_lower.contains("moldbot") { return Some("Moldbot".to_string()); }
        // LLM servers
        if banner_lower.contains("ollama") { return Some("Ollama".to_string()); }
        if banner_lower.contains("llama") || banner_lower.contains("ggml") { return Some("Llama.cpp".to_string()); }
        if banner_lower.contains("openai") { return Some("OpenAI API".to_string()); }
        if banner_lower.contains("vllm") { return Some("vLLM".to_string()); }
        if banner_lower.contains("text-generation") { return Some("TGI".to_string()); }
        // IDE/Editor agents
        if banner_lower.contains("cursor") { return Some("Cursor".to_string()); }
        if banner_lower.contains("aider") { return Some("Aider".to_string()); }
        if banner_lower.contains("continue") { return Some("Continue.dev".to_string()); }
        if banner_lower.contains("copilot") { return Some("GitHub Copilot".to_string()); }
        if banner_lower.contains("codeium") { return Some("Codeium".to_string()); }
        if banner_lower.contains("tabnine") { return Some("TabNine".to_string()); }
    }
    match port {
        11434 => Some("Ollama".to_string()),
        8501 => Some("Aider (Streamlit)".to_string()),
        18789 | 18793 => Some("OpenClaw".to_string()),
        _ => None,
    }
}

#[allow(dead_code)]
pub async fn deep_scan_device(
    device: &mut Device,
    progress_tx: Option<mpsc::Sender<ScanProgress>>,
) -> Result<()> {
    let all_ports: Vec<u16> = (1..=65535).collect();
    let total_ports = all_ports.len();
    let mut scanned = 0;
    let mut services = Vec::new();

    for chunk in all_ports.chunks(2000) {
        let chunk_services = scan_device_ports(&device.ip_address, chunk).await?;
        services.extend(chunk_services);
        scanned += chunk.len();
        if let Some(ref tx) = progress_tx {
            let _ = tx.send(ScanProgress {
                phase: ScanPhase::PortScan,
                devices_found: 1,
                current_device: Some(device.ip_address.clone()),
                ports_scanned: scanned,
                total_ports,
            }).await;
        }
    }
    device.services = services;
    Ok(())
}
