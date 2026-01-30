use crate::network_map::{lookup_vendor, Device, DeviceType};

/// Identify device type and vendor information
pub fn identify_device(device: &mut Device) {
    // Lookup vendor from MAC
    if device.vendor.is_none() {
        device.vendor = lookup_vendor(&device.mac_address).map(String::from);
    }

    // Infer device type from ports and vendor
    device.device_type = infer_device_type(device);

    // Collect detected agents
    device.detected_agents = device.services
        .iter()
        .filter_map(|s| s.detected_agent.clone())
        .collect();
}

/// Infer device type from open ports and vendor
fn infer_device_type(device: &Device) -> DeviceType {
    let ports: Vec<u16> = device.services.iter().map(|s| s.port).collect();
    let vendor = device.vendor.as_deref().unwrap_or("");
    let vendor_lower = vendor.to_lowercase();

    // Router detection: DNS + HTTP/HTTPS management
    if ports.contains(&53) && (ports.contains(&80) || ports.contains(&443)) {
        return DeviceType::Router;
    }

    // Apple iPhone/iPad detection
    if ports.contains(&62078) && vendor_lower.contains("apple") {
        return DeviceType::Phone;
    }

    // Apple devices without iPhone port
    if vendor_lower.contains("apple") {
        if ports.contains(&22) || ports.contains(&548) {
            return DeviceType::Computer;
        }
        return DeviceType::Phone;
    }

    // Smart TV detection
    if ports.contains(&8008) || ports.contains(&8009) || ports.contains(&9197) {
        return DeviceType::SmartTV;
    }
    if vendor_lower.contains("samsung") && !ports.contains(&22) {
        return DeviceType::SmartTV;
    }
    if vendor_lower.contains("lg") && !ports.contains(&22) {
        return DeviceType::SmartTV;
    }
    if vendor_lower.contains("roku") || vendor_lower.contains("sonos") {
        return DeviceType::SmartTV;
    }

    // Game console detection
    if vendor_lower.contains("nintendo") {
        return DeviceType::GameConsole;
    }
    if vendor_lower.contains("sony") && !ports.contains(&22) {
        return DeviceType::GameConsole;
    }

    // NAS detection
    if (ports.contains(&22) || ports.contains(&23))
        && (ports.contains(&445) || ports.contains(&548))
        && (ports.contains(&5000) || ports.contains(&5001))
    {
        return DeviceType::NAS;
    }
    if vendor_lower.contains("synology") || vendor_lower.contains("qnap") {
        return DeviceType::NAS;
    }

    // Printer detection
    if ports.contains(&9100) || ports.contains(&631) {
        return DeviceType::Printer;
    }
    if vendor_lower.contains("hp") && ports.contains(&80) && !ports.contains(&22) {
        return DeviceType::Printer;
    }

    // Computer/Laptop detection (SSH or RDP)
    if ports.contains(&22) || ports.contains(&3389) {
        if vendor_lower.contains("dell") || vendor_lower.contains("lenovo") || vendor_lower.contains("hp") {
            return DeviceType::Laptop;
        }
        return DeviceType::Computer;
    }

    // IoT detection
    if vendor_lower.contains("espressif") || vendor_lower.contains("amazon") {
        return DeviceType::IoT;
    }

    // Network equipment
    if vendor_lower.contains("tp-link") || vendor_lower.contains("netgear")
        || vendor_lower.contains("asus") || vendor_lower.contains("ubiquiti")
        || vendor_lower.contains("cisco")
    {
        if ports.contains(&80) || ports.contains(&443) {
            return DeviceType::Router;
        }
    }

    // Phone detection by vendor
    if vendor_lower.contains("samsung") || vendor_lower.contains("xiaomi")
        || vendor_lower.contains("google") || vendor_lower.contains("huawei")
    {
        return DeviceType::Phone;
    }

    // Raspberry Pi
    if vendor_lower.contains("raspberry") {
        return DeviceType::Computer;
    }

    DeviceType::Unknown
}

/// Identify all devices in a list
pub fn identify_all_devices(devices: &mut [Device]) {
    for device in devices {
        identify_device(device);
    }
}
