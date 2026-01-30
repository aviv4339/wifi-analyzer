use std::collections::HashMap;
use std::sync::OnceLock;

/// Lookup vendor name from MAC address prefix (OUI)
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let oui = get_oui_database();

    // Handle MAC addresses that may have single-digit octets (e.g., "0:E0:4C" instead of "00:E0:4C")
    // Split by common separators and pad each octet
    let parts: Vec<&str> = mac.split(|c| c == ':' || c == '-' || c == '.').collect();
    let normalized = if parts.len() >= 3 {
        // MAC with separators - pad each octet to 2 chars
        parts.iter()
            .take(3)
            .map(|p| format!("{:0>2}", p.to_uppercase()))
            .collect::<String>()
    } else {
        // No separators - just take first 6 hex chars
        mac.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(6)
            .collect::<String>()
            .to_uppercase()
    };

    if normalized.len() < 6 {
        return None;
    }

    // First check the OUI database (before checking for randomized)
    if let Some(vendor) = oui.get(normalized.as_str()).copied() {
        return Some(vendor);
    }

    // Check if locally administered address (second nibble is 2, 6, A, or E)
    // These are randomized MACs used by phones/laptops for privacy
    if let Some(second_char) = normalized.chars().nth(1) {
        if matches!(second_char, '2' | '6' | 'A' | 'E') {
            return Some("Private/Randomized");
        }
    }

    None
}

fn get_oui_database() -> &'static HashMap<&'static str, &'static str> {
    static OUI_DB: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

    OUI_DB.get_or_init(|| {
        let mut map = HashMap::with_capacity(300);

        // Apple (most common prefixes)
        for prefix in ["0026BB", "3C5AB4", "A4C361", "F0D1A9", "D0817A", "B8E856", "8866A5", "28E02C", "F0DCE2", "64A5C3", "48A195"] {
            map.insert(prefix, "Apple");
        }

        // Samsung
        for prefix in ["002119", "34145F", "50A4C8", "78BD9D", "84119E", "8C71F8", "9463D1", "ACE4B5", "BC8CCD"] {
            map.insert(prefix, "Samsung");
        }

        // Google
        for prefix in ["001A11", "3C5AB4", "54608C", "94EB2C", "F4F5D8", "F4F5E8"] {
            map.insert(prefix, "Google");
        }

        // Intel
        for prefix in ["001111", "001302", "001500", "0016EA", "001B21", "3C970E", "485B39", "5CE0C5", "8086F2"] {
            map.insert(prefix, "Intel");
        }

        // Espressif (ESP32/ESP8266 - used by Shelly, Sonoff, Tuya, and many IoT devices)
        for prefix in [
            "240AC4", "24B2DE", "2C3AE8", "30AEA4", "5CCF7F", "84CCA8", "A4CF12", "ECFABC",
            "08B61F", "08F9E0", "10521C", "10914F", "18FE34", "24D7EB", "2462AB", "283734",
            "2C9114", "2CF432", "2EC8EB", "3010DE", "303A64", "34864A", "34945B", "34AB95",
            "3C61EC", "3C71BF", "404CCA", "40F520", "44179B", "480FD2", "48E729", "4C11AE",
            "4C7525", "500291", "5C0133", "5CCF7F", "60019D", "60A5E2", "64A2F9", "64B7B7",
            "683E34", "68B6B3", "68C63A", "78E36D", "7C87CE", "807D3A", "84F703", "880BC9",
            "8C4B14", "8C7C92", "8CAAB5", "90380C", "98CDAC", "98F4AB", "A020A6", "A0D4F0",
            "A4E57C", "A8032A", "AC0BFB", "AC67B2", "B0B21C", "B4E62D", "BC8A8C", "BCDD37",
            "C45BBE", "C8C9A3", "CC50E3", "D8A01D", "D8BFC0", "D8F15B", "DC4F22", "E0E2E6",
            "E8DB84", "EC6260", "EC94D3", "F008D1", "F4CFA2", "FC019B", "FCF5C4",
        ] {
            map.insert(prefix, "Espressif");
        }

        // Shelly / Allterco (some devices have Allterco-specific OUI)
        for prefix in ["34945B", "483FDA", "84CCA8", "E8DB84", "EC6260"] {
            map.insert(prefix, "Shelly");
        }

        // Amazon
        for prefix in ["0C47C9", "18B4A6", "34D270", "40B4CD", "50DCE7", "687D6B", "747548", "A002DC", "FC65DE"] {
            map.insert(prefix, "Amazon");
        }

        // IANA multicast (01:00:5E is IPv4 multicast)
        map.insert("01005E", "Multicast");

        // Xiaomi
        for prefix in ["00EC0A", "0C1DAF", "286C07", "34CE00", "50A728", "64B473", "74D4DD", "78112F", "9C99A0", "AC3743", "F8A45F"] {
            map.insert(prefix, "Xiaomi");
        }

        // Microsoft
        for prefix in ["001DD8", "0050F2", "28186D", "50579C", "7CB27D", "B483E7", "C83DD4"] {
            map.insert(prefix, "Microsoft");
        }

        // Realtek (common network chipsets)
        for prefix in ["00E04C", "00044B", "001F1F", "20CF30", "48E24B", "52540B", "54E1AD", "74DA38",
                       "801F02", "94DE80", "98541B", "D8EB46", "E04F43", "EC086B"] {
            map.insert(prefix, "Realtek");
        }

        // Intel
        for prefix in ["001111", "001302", "001517", "0016EA", "002314", "00215D", "3413E8", "384697",
                       "485D36", "5CC5D4", "606720", "645A04", "6C883C", "7C5CF8", "80861F", "848F69",
                       "94659C", "985FD3", "A0369F", "A4C494", "B8088C", "CC2F71", "DC536C", "E4B97A"] {
            map.insert(prefix, "Intel");
        }

        // TP-Link
        for prefix in ["001470", "14CC20", "1C3BF3", "30B5C2", "503EAA", "54E6FC", "90F652", "C025E9", "D80D17"] {
            map.insert(prefix, "TP-Link");
        }

        // Netgear
        for prefix in ["0024B2", "00265A", "20E52A", "28C68E", "6038E0", "744401", "9C3DCF", "A42B8C", "C03F0E"] {
            map.insert(prefix, "Netgear");
        }

        // ASUS / ASUSTek
        for prefix in ["001731", "04421A", "08606E", "14DAE9", "2C4D54", "50465D", "74D02B", "ACDE48", "F46D04",
                       "C87F54", "1831BF", "2CFDA1", "34977A", "38D547", "4CEDFB", "60A44C", "707781", "90E6BA",
                       "9C5C8E", "AC9E17", "B06EBF", "BC5C4C", "D850E6", "E03F49", "F832E4", "FCAA14"] {
            map.insert(prefix, "ASUS");
        }

        // Dell
        for prefix in ["001422", "14187D", "149182", "18A99B", "28F10E", "34E6D7", "5C260A", "74E6E2", "D89EF3"] {
            map.insert(prefix, "Dell");
        }

        // HP
        for prefix in ["001083", "001185", "001635", "001708", "10604B", "28924A", "3C4A92", "80CE62", "D42C44"] {
            map.insert(prefix, "HP");
        }

        // Lenovo
        for prefix in ["002482", "347083", "4C5262", "60D819", "6C0B84", "C4D0E3", "E83934", "F82FA8"] {
            map.insert(prefix, "Lenovo");
        }

        // Synology
        for prefix in ["0011A0", "001132"] {
            map.insert(prefix, "Synology");
        }

        // Raspberry Pi
        for prefix in ["B827EB", "DCA632", "E45F01"] {
            map.insert(prefix, "Raspberry Pi");
        }

        // Sony
        for prefix in ["000AD9", "001315", "001A80", "28A02B", "40B837", "8C4909", "A85B61", "F8DA0C"] {
            map.insert(prefix, "Sony");
        }

        // LG
        for prefix in ["001256", "10F96F", "340804", "64899A", "78F882", "9CA39B", "A8F274", "C83870"] {
            map.insert(prefix, "LG");
        }

        // Nintendo
        for prefix in ["001656", "002331", "34AF2C", "582F40", "7CBB8A", "98B6E9", "A438CC", "E84ECE"] {
            map.insert(prefix, "Nintendo");
        }

        // Ubiquiti
        for prefix in ["00156D", "002722", "18E829", "44D9E7", "68D79A", "788A20", "802AA8", "FCFFD4"] {
            map.insert(prefix, "Ubiquiti");
        }

        // Xiaomi
        for prefix in ["0C1DAF", "28E31F", "50647B", "64B473", "7C1DD9", "98FAE3", "AC1E92", "F0B429"] {
            map.insert(prefix, "Xiaomi");
        }

        // Huawei
        for prefix in ["000D9E", "001882", "0025D7", "24DF6A", "5C7D5E", "70700D", "88CEFA", "C8D15E"] {
            map.insert(prefix, "Huawei");
        }

        // Cisco
        for prefix in ["000142", "001A6D", "002155", "00259C", "28940F", "38ED18", "5475D0", "8851FB"] {
            map.insert(prefix, "Cisco");
        }

        // Sonos
        for prefix in ["000E58", "5494F3", "5CAAFD", "78283C", "94DAAE", "B8E937"] {
            map.insert(prefix, "Sonos");
        }

        // Roku
        for prefix in ["08059E", "B0A737", "C8FC18", "D03478", "DC3A5E"] {
            map.insert(prefix, "Roku");
        }

        map
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_apple() {
        assert_eq!(lookup_vendor("00:26:BB:12:34:56"), Some("Apple"));
        assert_eq!(lookup_vendor("0026bb123456"), Some("Apple"));
    }

    #[test]
    fn test_lookup_unknown() {
        assert_eq!(lookup_vendor("FF:FF:FF:FF:FF:FF"), None);
    }

    #[test]
    fn test_lookup_espressif() {
        assert_eq!(lookup_vendor("5C:CF:7F:12:34:56"), Some("Espressif"));
    }
}
