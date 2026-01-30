use chrono::{DateTime, Utc};

/// A device discovered on the network
#[derive(Debug, Clone)]
pub struct Device {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: DeviceType,
    pub custom_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub is_online: bool,
    pub services: Vec<Service>,
    pub detected_agents: Vec<String>,
}

impl Device {
    pub fn new(mac_address: String, ip_address: String) -> Self {
        let now = Utc::now();
        Self {
            mac_address,
            ip_address,
            hostname: None,
            vendor: None,
            device_type: DeviceType::Unknown,
            custom_name: None,
            first_seen: now,
            last_seen: now,
            is_online: true,
            services: Vec::new(),
            detected_agents: Vec::new(),
        }
    }

    /// Get display name (custom name > hostname > vendor + type > MAC)
    pub fn display_name(&self) -> String {
        if let Some(ref name) = self.custom_name {
            return name.clone();
        }
        if let Some(ref hostname) = self.hostname {
            return hostname.clone();
        }
        if let Some(ref vendor) = self.vendor {
            return format!("{} {}", vendor, self.device_type);
        }
        self.mac_address.clone()
    }
}

/// Device type inferred from ports and vendor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceType {
    Router,
    Phone,
    Computer,
    Laptop,
    Tablet,
    SmartTV,
    Printer,
    NAS,
    IoT,
    GameConsole,
    #[default]
    Unknown,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Router => write!(f, "Router"),
            DeviceType::Phone => write!(f, "Phone"),
            DeviceType::Computer => write!(f, "Computer"),
            DeviceType::Laptop => write!(f, "Laptop"),
            DeviceType::Tablet => write!(f, "Tablet"),
            DeviceType::SmartTV => write!(f, "Smart TV"),
            DeviceType::Printer => write!(f, "Printer"),
            DeviceType::NAS => write!(f, "NAS"),
            DeviceType::IoT => write!(f, "IoT Device"),
            DeviceType::GameConsole => write!(f, "Game Console"),
            DeviceType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A service/port discovered on a device
#[derive(Debug, Clone)]
pub struct Service {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub detected_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Progress of a network scan
#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub phase: ScanPhase,
    pub devices_found: usize,
    pub current_device: Option<String>,
    pub ports_scanned: usize,
    pub total_ports: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    Discovery,
    PortScan,
    Identification,
    Complete,
}

impl std::fmt::Display for ScanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanPhase::Discovery => write!(f, "Discovering devices"),
            ScanPhase::PortScan => write!(f, "Scanning ports"),
            ScanPhase::Identification => write!(f, "Identifying devices"),
            ScanPhase::Complete => write!(f, "Complete"),
        }
    }
}

/// Common ports to scan in quick mode
pub const COMMON_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    443,   // HTTPS
    139,   // NetBIOS
    445,   // SMB
    548,   // AFP
    554,   // RTSP
    3389,  // RDP
    5000,  // Synology/UPnP
    5001,  // Synology SSL
    8080,  // Alt HTTP
    8443,  // Alt HTTPS
    9100,  // Printer
    62078, // Apple iDevice
    8008,  // Chromecast
    8009,  // Chromecast
    // AI Agent ports
    3000,  // Dev servers / Claude Code
    3001,
    8000,  // Python servers
    8001,
    11434, // Ollama
    9229,  // Node.js debug
    8501,  // Streamlit (Aider)
];
