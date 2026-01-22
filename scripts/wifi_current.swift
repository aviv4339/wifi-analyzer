#!/usr/bin/env swift

import Foundation
import CoreWLAN

// Get the default WiFi interface
guard let interface = CWWiFiClient.shared().interface() else {
    fputs("Error: No WiFi interface found\n", stderr)
    exit(1)
}

// Get current connection info
if let ssid = interface.ssid() {
    print("SSID:\(ssid)")
} else {
    print("SSID:")
}

if let bssid = interface.bssid() {
    print("BSSID:\(bssid)")
} else {
    print("BSSID:")
}
