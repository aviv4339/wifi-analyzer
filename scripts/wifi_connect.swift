#!/usr/bin/env swift

import Foundation
import CoreWLAN

// Usage: wifi_connect.swift <SSID>
guard CommandLine.arguments.count >= 2 else {
    fputs("Usage: wifi_connect.swift <SSID>\n", stderr)
    exit(1)
}

let targetSSID = CommandLine.arguments[1]

// Get the default WiFi interface
guard let interface = CWWiFiClient.shared().interface() else {
    fputs("ERROR:No WiFi interface found\n", stderr)
    exit(1)
}

// First, scan to find the network
do {
    let networks = try interface.scanForNetworks(withSSID: targetSSID.data(using: .utf8))

    guard let targetNetwork = networks.first else {
        fputs("ERROR:Network '\(targetSSID)' not found\n", stderr)
        exit(1)
    }

    // Try to associate (for known networks, password is in keychain)
    do {
        try interface.associate(to: targetNetwork, password: nil)
        print("SUCCESS:Connected to \(targetSSID)")
        exit(0)
    } catch let error as NSError {
        // If it needs a password and we don't have it, this will fail
        fputs("ERROR:\(error.localizedDescription)\n", stderr)
        exit(1)
    }
} catch {
    fputs("ERROR:Scan failed - \(error.localizedDescription)\n", stderr)
    exit(1)
}
