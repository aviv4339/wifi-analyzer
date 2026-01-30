use std::collections::HashMap;
use std::sync::OnceLock;

/// Lookup vendor name from MAC address prefix (OUI)
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let oui = get_oui_database();
    let normalized: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_uppercase();

    if normalized.len() < 6 {
        return None;
    }
    oui.get(normalized.as_str()).copied()
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

        // Espressif (IoT)
        for prefix in ["240AC4", "24B2DE", "2C3AE8", "30AEA4", "5CCF7F", "84CCA8", "A4CF12", "ECFABC"] {
            map.insert(prefix, "Espressif");
        }

        // Amazon
        for prefix in ["0C47C9", "18B4A6", "34D270", "40B4CD", "50DCE7", "687D6B", "747548", "A002DC", "FC65DE"] {
            map.insert(prefix, "Amazon");
        }

        // Microsoft
        for prefix in ["001DD8", "0050F2", "28186D", "50579C", "7CB27D", "B483E7", "C83DD4"] {
            map.insert(prefix, "Microsoft");
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
