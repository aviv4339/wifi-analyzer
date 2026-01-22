#!/usr/bin/env swift

import Foundation
import CoreWLAN

// Get the default WiFi interface
guard let interface = CWWiFiClient.shared().interface() else {
    fputs("Error: No WiFi interface found\n", stderr)
    exit(1)
}

// Perform a scan
do {
    let networks = try interface.scanForNetworks(withSSID: nil)

    // Output in a parseable format: SSID|BSSID|CHANNEL|RSSI|SECURITY
    for network in networks {
        let ssid = network.ssid ?? "<Hidden>"
        let bssid = network.bssid ?? ""
        let channel = network.wlanChannel?.channelNumber ?? 0
        let rssi = network.rssiValue

        // Determine security
        var security = "Unknown"
        if network.supportsSecurity(.none) || network.supportsSecurity(.dynamicWEP) == false && network.supportsSecurity(.enterprise) == false && network.supportsSecurity(.personal) == false {
            if !network.supportsSecurity(.wpaPersonal) && !network.supportsSecurity(.wpa2Personal) && !network.supportsSecurity(.wpa3Personal) {
                security = "Open"
            }
        }
        if network.supportsSecurity(.WEP) {
            security = "WEP"
        }
        if network.supportsSecurity(.wpaPersonal) || network.supportsSecurity(.wpaEnterprise) {
            security = "WPA"
        }
        if network.supportsSecurity(.wpa2Personal) || network.supportsSecurity(.wpa2Enterprise) {
            security = "WPA2"
        }
        if network.supportsSecurity(.wpa3Personal) || network.supportsSecurity(.wpa3Enterprise) || network.supportsSecurity(.wpa3Transition) {
            security = "WPA3"
        }

        print("\(ssid)|\(bssid)|\(channel)|\(rssi)|\(security)")
    }
} catch {
    fputs("Error scanning: \(error.localizedDescription)\n", stderr)
    exit(1)
}
