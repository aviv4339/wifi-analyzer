use chrono::{DateTime, Utc};
use color_eyre::Result;
use duckdb::{params, Connection};
use std::path::Path;

/// Database connection wrapper for WiFi network persistence
pub struct Database {
    conn: Connection,
}

/// A named location where networks are scanned
#[derive(Debug, Clone)]
pub struct Location {
    pub id: i64,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

/// A network record from the database
#[derive(Debug, Clone)]
pub struct DbNetwork {
    pub id: i64,
    pub bssid: String,
    pub ssid: String,
}

/// Record to insert into scan_results
pub struct ScanResultRecord {
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub signal_dbm: i32,
    pub security: String,
    pub frequency_band: String,
    pub score: u8,
}

impl Database {
    /// Open or create a database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing)
    #[allow(dead_code)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Initialize the database schema
    fn initialize_schema(&self) -> Result<()> {
        // Create sequences for auto-increment IDs
        self.conn.execute_batch(
            r#"
            CREATE SEQUENCE IF NOT EXISTS seq_locations_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_networks_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_scans_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_scan_results_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_connections_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_known_networks_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_devices_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_device_services_id START 1;
            CREATE SEQUENCE IF NOT EXISTS seq_device_scans_id START 1;
            "#,
        )?;

        // Note: Avoiding REFERENCES clauses due to DuckDB FK limitations
        // Referential integrity is maintained by application logic
        self.conn.execute_batch(
            r#"
            -- Locations: named scanning locations
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_locations_id'),
                name TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Networks: unique by BSSID (MAC address)
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_networks_id'),
                bssid TEXT NOT NULL UNIQUE,
                ssid TEXT NOT NULL,
                first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Scans: individual scan events
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_scans_id'),
                location_id INTEGER NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Scan results: network observations per scan
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_scan_results_id'),
                scan_id INTEGER NOT NULL,
                network_id INTEGER NOT NULL,
                channel INTEGER NOT NULL,
                signal_dbm INTEGER NOT NULL,
                security TEXT NOT NULL,
                frequency_band TEXT NOT NULL,
                score INTEGER NOT NULL
            );

            -- Indexes for common queries
            CREATE INDEX IF NOT EXISTS idx_scan_results_network ON scan_results(network_id);
            CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_location ON scans(location_id);
            CREATE INDEX IF NOT EXISTS idx_networks_ssid ON networks(ssid);

            -- Connections: tracks each connection event with stats
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_connections_id'),
                network_id INTEGER NOT NULL,
                connected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                disconnected_at TIMESTAMP,
                local_ip TEXT,
                public_ip TEXT,
                download_mbps REAL,
                upload_mbps REAL
            );
            CREATE INDEX IF NOT EXISTS idx_connections_network ON connections(network_id);
            CREATE INDEX IF NOT EXISTS idx_connections_time ON connections(connected_at DESC);

            -- Known networks: imported from macOS plist
            CREATE TABLE IF NOT EXISTS known_networks (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_known_networks_id'),
                ssid TEXT NOT NULL UNIQUE,
                last_connected_at TIMESTAMP,
                added_at TIMESTAMP,
                imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- Devices: discovered network devices
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_devices_id'),
                mac_address TEXT NOT NULL UNIQUE,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                device_type TEXT,
                custom_name TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                network_bssid TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);

            -- Device services: open ports on devices
            CREATE TABLE IF NOT EXISTS device_services (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_device_services_id'),
                device_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service_name TEXT,
                banner TEXT,
                detected_agent TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(device_id, port, protocol)
            );
            CREATE INDEX IF NOT EXISTS idx_device_services_device ON device_services(device_id);

            -- Device scan history
            CREATE TABLE IF NOT EXISTS device_scans (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_device_scans_id'),
                network_bssid TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                devices_found INTEGER,
                scan_type TEXT
            );
            "#,
        )?;
        Ok(())
    }

    /// Create a new location or get existing one by name
    pub fn create_or_get_location(&self, name: &str) -> Result<i64> {
        // Try to get existing location
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM locations WHERE name = ?")?;
        let mut rows = stmt.query(params![name])?;

        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            // Update last_used_at
            self.conn.execute(
                "UPDATE locations SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
                params![id],
            )?;
            return Ok(id);
        }

        // Create new location
        self.conn.execute(
            "INSERT INTO locations (name) VALUES (?)",
            params![name],
        )?;

        // Get the inserted ID
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM locations WHERE name = ?")?;
        let mut rows = stmt.query(params![name])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to retrieve inserted location")
        })?;
        Ok(row.get(0)?)
    }

    /// List all known locations
    pub fn list_locations(&self) -> Result<Vec<Location>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, CAST(created_at AS VARCHAR), CAST(last_used_at AS VARCHAR) FROM locations ORDER BY last_used_at DESC",
        )?;
        let mut rows = stmt.query([])?;
        let mut locations = Vec::new();

        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let created_at: String = row.get(2)?;
            let last_used_at: String = row.get(3)?;

            locations.push(Location {
                id,
                name,
                created_at: parse_timestamp(&created_at),
                last_used_at: parse_timestamp(&last_used_at),
            });
        }

        Ok(locations)
    }

    /// Insert or update a network by BSSID
    fn upsert_network(&self, bssid: &str, ssid: &str) -> Result<i64> {
        let bssid_upper = bssid.to_uppercase();

        // Try to get existing network
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM networks WHERE bssid = ?")?;
        let mut rows = stmt.query(params![bssid_upper])?;

        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            // Update last_seen and potentially the SSID (it can change)
            self.conn.execute(
                "UPDATE networks SET ssid = ?, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?",
                params![ssid, id],
            )?;
            return Ok(id);
        }

        // Create new network
        self.conn.execute(
            "INSERT INTO networks (bssid, ssid) VALUES (?, ?)",
            params![bssid_upper, ssid],
        )?;

        // Get the inserted ID
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM networks WHERE bssid = ?")?;
        let mut rows = stmt.query(params![bssid_upper])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to retrieve inserted network")
        })?;
        Ok(row.get(0)?)
    }

    /// Create a new scan record
    pub fn create_scan(&self, location_id: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO scans (location_id) VALUES (?)",
            params![location_id],
        )?;

        // Get the last inserted rowid
        let mut stmt = self.conn.prepare(
            "SELECT id FROM scans WHERE location_id = ? ORDER BY id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![location_id])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to retrieve inserted scan")
        })?;
        Ok(row.get(0)?)
    }

    /// Record scan results in batch
    pub fn record_scan_results(&self, scan_id: i64, results: &[ScanResultRecord]) -> Result<()> {
        for result in results {
            // Upsert the network first
            let network_id = self.upsert_network(&result.bssid, &result.ssid)?;

            // Insert the scan result (each scan_id + network_id combination is unique)
            self.conn.execute(
                r#"
                INSERT INTO scan_results (scan_id, network_id, channel, signal_dbm, security, frequency_band, score)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    scan_id,
                    network_id,
                    result.channel as i32,
                    result.signal_dbm,
                    result.security,
                    result.frequency_band,
                    result.score as i32
                ],
            )?;
        }

        Ok(())
    }

    /// Get signal history for a network (by BSSID)
    #[allow(dead_code)]
    pub fn get_signal_history(&self, bssid: &str, limit: usize) -> Result<Vec<i32>> {
        let bssid_upper = bssid.to_uppercase();
        let mut stmt = self.conn.prepare(
            r#"
            SELECT sr.signal_dbm
            FROM scan_results sr
            JOIN networks n ON sr.network_id = n.id
            JOIN scans s ON sr.scan_id = s.id
            WHERE n.bssid = ?
            ORDER BY s.scanned_at DESC
            LIMIT ?
            "#,
        )?;
        let mut rows = stmt.query(params![bssid_upper, limit as i64])?;
        let mut history = Vec::new();

        while let Some(row) = rows.next()? {
            history.push(row.get(0)?);
        }

        // Reverse to get oldest-to-newest order
        history.reverse();
        Ok(history)
    }

    /// Load all networks for a location with their most recent scan data
    /// Used to restore state on startup
    pub fn load_networks_for_location(&self, location_id: i64) -> Result<Vec<LoadedNetwork>> {
        let mut stmt = self.conn.prepare(
            r#"
            WITH latest_scan AS (
                SELECT
                    sr.network_id,
                    sr.channel,
                    sr.signal_dbm,
                    sr.security,
                    sr.frequency_band,
                    sr.score,
                    s.scanned_at,
                    ROW_NUMBER() OVER (PARTITION BY sr.network_id ORDER BY s.scanned_at DESC) as rn
                FROM scan_results sr
                JOIN scans s ON sr.scan_id = s.id
                WHERE s.location_id = ?
            )
            SELECT
                n.bssid,
                n.ssid,
                ls.channel,
                ls.signal_dbm,
                ls.security,
                ls.frequency_band,
                ls.score,
                CAST(ls.scanned_at AS VARCHAR)
            FROM networks n
            JOIN latest_scan ls ON ls.network_id = n.id
            WHERE ls.rn = 1
            ORDER BY ls.score DESC
            "#,
        )?;
        let mut rows = stmt.query(params![location_id])?;
        let mut networks = Vec::new();

        while let Some(row) = rows.next()? {
            let scanned_at_str: String = row.get(7)?;
            networks.push(LoadedNetwork {
                bssid: row.get(0)?,
                ssid: row.get(1)?,
                channel: row.get::<_, i32>(2)? as u8,
                signal_dbm: row.get(3)?,
                security: row.get(4)?,
                frequency_band: row.get(5)?,
                score: row.get::<_, i32>(6)? as u8,
                last_seen: parse_timestamp(&scanned_at_str),
            });
        }

        Ok(networks)
    }

    /// Get networks seen at a location with their most recent stats
    #[allow(dead_code)]
    pub fn get_networks_at_location(&self, location_id: i64) -> Result<Vec<NetworkSummary>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                n.bssid,
                n.ssid,
                AVG(sr.signal_dbm) as avg_signal,
                AVG(sr.score) as avg_score,
                COUNT(*) as times_seen,
                (SELECT sr2.signal_dbm
                 FROM scan_results sr2
                 JOIN scans s2 ON sr2.scan_id = s2.id
                 WHERE sr2.network_id = n.id AND s2.location_id = ?
                 ORDER BY s2.scanned_at DESC LIMIT 1) as last_signal,
                (SELECT sr2.score
                 FROM scan_results sr2
                 JOIN scans s2 ON sr2.scan_id = s2.id
                 WHERE sr2.network_id = n.id AND s2.location_id = ?
                 ORDER BY s2.scanned_at DESC LIMIT 1) as last_score
            FROM networks n
            JOIN scan_results sr ON sr.network_id = n.id
            JOIN scans s ON sr.scan_id = s.id
            WHERE s.location_id = ?
            GROUP BY n.id
            ORDER BY avg_score DESC
            "#,
        )?;
        let mut rows = stmt.query(params![location_id, location_id, location_id])?;
        let mut summaries = Vec::new();

        while let Some(row) = rows.next()? {
            summaries.push(NetworkSummary {
                bssid: row.get(0)?,
                ssid: row.get(1)?,
                avg_signal_dbm: row.get(2)?,
                avg_score: row.get(3)?,
                times_seen: row.get(4)?,
                last_signal_dbm: row.get(5)?,
                last_score: row.get(6)?,
            });
        }

        Ok(summaries)
    }

    // ========== Connection Management ==========

    /// Get network ID by BSSID (public method)
    pub fn get_network_id_by_bssid(&self, bssid: &str) -> Result<Option<i64>> {
        let bssid_upper = bssid.to_uppercase();
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM networks WHERE bssid = ?")?;
        let mut rows = stmt.query(params![bssid_upper])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Insert a new connection record
    pub fn insert_connection(
        &self,
        network_id: i64,
        local_ip: Option<&str>,
        public_ip: Option<&str>,
        download_mbps: Option<f64>,
        upload_mbps: Option<f64>,
    ) -> Result<i64> {
        self.conn.execute(
            r#"
            INSERT INTO connections (network_id, local_ip, public_ip, download_mbps, upload_mbps)
            VALUES (?, ?, ?, ?, ?)
            "#,
            params![network_id, local_ip, public_ip, download_mbps, upload_mbps],
        )?;

        // Get the inserted ID
        let mut stmt = self.conn.prepare(
            "SELECT id FROM connections WHERE network_id = ? ORDER BY id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![network_id])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to retrieve inserted connection")
        })?;
        Ok(row.get(0)?)
    }

    /// Update connection with disconnection time
    pub fn update_connection_disconnected(&self, connection_id: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE connections SET disconnected_at = CURRENT_TIMESTAMP WHERE id = ?",
            params![connection_id],
        )?;
        Ok(())
    }

    /// Get connection history for a network
    pub fn get_connection_history(&self, network_id: i64, limit: usize) -> Result<Vec<ConnectionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                id,
                network_id,
                CAST(connected_at AS VARCHAR),
                CAST(disconnected_at AS VARCHAR),
                local_ip,
                public_ip,
                download_mbps,
                upload_mbps
            FROM connections
            WHERE network_id = ?
            ORDER BY connected_at DESC
            LIMIT ?
            "#,
        )?;
        let mut rows = stmt.query(params![network_id, limit as i64])?;
        let mut records = Vec::new();

        while let Some(row) = rows.next()? {
            let connected_at_str: String = row.get(2)?;
            let disconnected_at_str: Option<String> = row.get(3)?;

            records.push(ConnectionRecord {
                id: row.get(0)?,
                network_id: row.get(1)?,
                connected_at: parse_timestamp(&connected_at_str),
                disconnected_at: disconnected_at_str.map(|s| parse_timestamp(&s)),
                local_ip: row.get(4)?,
                public_ip: row.get(5)?,
                download_mbps: row.get(6)?,
                upload_mbps: row.get(7)?,
            });
        }

        Ok(records)
    }

    /// Get recent distinct IPs for a network
    pub fn get_recent_ips(&self, network_id: i64, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT DISTINCT local_ip
            FROM connections
            WHERE network_id = ? AND local_ip IS NOT NULL
            ORDER BY connected_at DESC
            LIMIT ?
            "#,
        )?;
        let mut rows = stmt.query(params![network_id, limit as i64])?;
        let mut ips = Vec::new();

        while let Some(row) = rows.next()? {
            let ip: String = row.get(0)?;
            ips.push(ip);
        }

        Ok(ips)
    }

    /// Get the connection count for a network
    pub fn get_connection_count(&self, network_id: i64) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*) FROM connections WHERE network_id = ?",
        )?;
        let mut rows = stmt.query(params![network_id])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to get connection count")
        })?;
        Ok(row.get(0)?)
    }

    /// Get the most recent connection for a network
    pub fn get_last_connection(&self, network_id: i64) -> Result<Option<ConnectionRecord>> {
        let records = self.get_connection_history(network_id, 1)?;
        Ok(records.into_iter().next())
    }

    // ========== Known Networks Management ==========

    /// Import a known network from plist
    pub fn import_known_network(
        &self,
        ssid: &str,
        last_connected_at: Option<DateTime<Utc>>,
        added_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        // Use INSERT OR IGNORE to skip duplicates
        let last_connected_str = last_connected_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());
        let added_str = added_at.map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string());

        self.conn.execute(
            r#"
            INSERT INTO known_networks (ssid, last_connected_at, added_at)
            VALUES (?, ?, ?)
            ON CONFLICT (ssid) DO UPDATE SET
                last_connected_at = COALESCE(EXCLUDED.last_connected_at, known_networks.last_connected_at),
                added_at = COALESCE(EXCLUDED.added_at, known_networks.added_at)
            "#,
            params![ssid, last_connected_str, added_str],
        )?;
        Ok(())
    }

    /// Check if an SSID is a known network
    pub fn is_known_network(&self, ssid: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare(
            "SELECT 1 FROM known_networks WHERE ssid = ? LIMIT 1",
        )?;
        let mut rows = stmt.query(params![ssid])?;
        Ok(rows.next()?.is_some())
    }

    /// Get all known networks
    pub fn get_known_networks(&self) -> Result<Vec<KnownNetwork>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                id,
                ssid,
                CAST(last_connected_at AS VARCHAR),
                CAST(added_at AS VARCHAR),
                CAST(imported_at AS VARCHAR)
            FROM known_networks
            ORDER BY last_connected_at DESC NULLS LAST
            "#,
        )?;
        let mut rows = stmt.query([])?;
        let mut networks = Vec::new();

        while let Some(row) = rows.next()? {
            let last_connected_str: Option<String> = row.get(2)?;
            let added_str: Option<String> = row.get(3)?;
            let imported_str: String = row.get(4)?;

            networks.push(KnownNetwork {
                id: row.get(0)?,
                ssid: row.get(1)?,
                last_connected_at: last_connected_str.map(|s| parse_timestamp(&s)),
                added_at: added_str.map(|s| parse_timestamp(&s)),
                imported_at: parse_timestamp(&imported_str),
            });
        }

        Ok(networks)
    }

    /// Get known network count (to check if import is needed)
    pub fn get_known_networks_count(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM known_networks")?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.ok_or_else(|| {
            color_eyre::eyre::eyre!("Failed to get known networks count")
        })?;
        Ok(row.get(0)?)
    }

    // ========== Device Management ==========

    /// Insert or update a device
    pub fn upsert_device(
        &self,
        mac_address: &str,
        ip_address: &str,
        hostname: Option<&str>,
        vendor: Option<&str>,
        device_type: &str,
        custom_name: Option<&str>,
        network_bssid: Option<&str>,
    ) -> Result<i64> {
        let mac_upper = mac_address.to_uppercase();
        let mut stmt = self.conn.prepare("SELECT id FROM devices WHERE mac_address = ?")?;
        let mut rows = stmt.query(params![mac_upper])?;

        if let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            self.conn.execute(
                r#"UPDATE devices SET ip_address = ?, hostname = COALESCE(?, hostname),
                   vendor = COALESCE(?, vendor), device_type = ?,
                   custom_name = COALESCE(?, custom_name), network_bssid = COALESCE(?, network_bssid),
                   last_seen = CURRENT_TIMESTAMP WHERE id = ?"#,
                params![ip_address, hostname, vendor, device_type, custom_name, network_bssid, id],
            )?;
            return Ok(id);
        }

        self.conn.execute(
            r#"INSERT INTO devices (mac_address, ip_address, hostname, vendor, device_type, custom_name, network_bssid)
               VALUES (?, ?, ?, ?, ?, ?, ?)"#,
            params![mac_upper, ip_address, hostname, vendor, device_type, custom_name, network_bssid],
        )?;

        let mut stmt = self.conn.prepare("SELECT id FROM devices WHERE mac_address = ?")?;
        let mut rows = stmt.query(params![mac_upper])?;
        let row = rows.next()?.ok_or_else(|| color_eyre::eyre::eyre!("Failed to retrieve inserted device"))?;
        Ok(row.get(0)?)
    }

    /// Update device custom name
    pub fn update_device_name(&self, mac_address: &str, custom_name: &str) -> Result<()> {
        let mac_upper = mac_address.to_uppercase();
        self.conn.execute("UPDATE devices SET custom_name = ? WHERE mac_address = ?", params![custom_name, mac_upper])?;
        Ok(())
    }

    /// Insert or update a service for a device
    pub fn upsert_device_service(
        &self,
        device_id: i64,
        port: u16,
        protocol: &str,
        service_name: Option<&str>,
        banner: Option<&str>,
        detected_agent: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            r#"INSERT INTO device_services (device_id, port, protocol, service_name, banner, detected_agent)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (device_id, port, protocol) DO UPDATE SET
                   service_name = COALESCE(EXCLUDED.service_name, device_services.service_name),
                   banner = COALESCE(EXCLUDED.banner, device_services.banner),
                   detected_agent = COALESCE(EXCLUDED.detected_agent, device_services.detected_agent),
                   last_seen = CURRENT_TIMESTAMP"#,
            params![device_id, port as i32, protocol, service_name, banner, detected_agent],
        )?;
        Ok(())
    }

    /// Get all devices for a network
    pub fn get_devices_for_network(&self, network_bssid: Option<&str>) -> Result<Vec<DeviceRecord>> {
        let query = if network_bssid.is_some() {
            r#"SELECT id, mac_address, ip_address, hostname, vendor, device_type, custom_name,
               CAST(first_seen AS VARCHAR), CAST(last_seen AS VARCHAR), network_bssid
               FROM devices WHERE network_bssid = ? ORDER BY last_seen DESC"#
        } else {
            r#"SELECT id, mac_address, ip_address, hostname, vendor, device_type, custom_name,
               CAST(first_seen AS VARCHAR), CAST(last_seen AS VARCHAR), network_bssid
               FROM devices ORDER BY last_seen DESC"#
        };

        let mut stmt = self.conn.prepare(query)?;
        let mut rows = if let Some(bssid) = network_bssid {
            stmt.query(params![bssid])?
        } else {
            stmt.query([])?
        };

        let mut devices = Vec::new();
        while let Some(row) = rows.next()? {
            let first_seen_str: String = row.get(7)?;
            let last_seen_str: String = row.get(8)?;
            devices.push(DeviceRecord {
                id: row.get(0)?,
                mac_address: row.get(1)?,
                ip_address: row.get(2)?,
                hostname: row.get(3)?,
                vendor: row.get(4)?,
                device_type: row.get(5)?,
                custom_name: row.get(6)?,
                first_seen: parse_timestamp(&first_seen_str),
                last_seen: parse_timestamp(&last_seen_str),
                network_bssid: row.get(9)?,
            });
        }
        Ok(devices)
    }

    /// Get services for a device
    pub fn get_device_services(&self, device_id: i64) -> Result<Vec<ServiceRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, port, protocol, service_name, banner, detected_agent FROM device_services WHERE device_id = ? ORDER BY port"
        )?;
        let mut rows = stmt.query(params![device_id])?;
        let mut services = Vec::new();
        while let Some(row) = rows.next()? {
            services.push(ServiceRecord {
                id: row.get(0)?,
                port: row.get::<_, i32>(1)? as u16,
                protocol: row.get(2)?,
                service_name: row.get(3)?,
                banner: row.get(4)?,
                detected_agent: row.get(5)?,
            });
        }
        Ok(services)
    }

    /// Create a device scan record
    pub fn create_device_scan(&self, network_bssid: Option<&str>, scan_type: &str) -> Result<i64> {
        self.conn.execute("INSERT INTO device_scans (network_bssid, scan_type) VALUES (?, ?)", params![network_bssid, scan_type])?;
        let mut stmt = self.conn.prepare("SELECT id FROM device_scans ORDER BY id DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.ok_or_else(|| color_eyre::eyre::eyre!("Failed to retrieve inserted device scan"))?;
        Ok(row.get(0)?)
    }

    /// Complete a device scan
    pub fn complete_device_scan(&self, scan_id: i64, devices_found: usize) -> Result<()> {
        self.conn.execute(
            "UPDATE device_scans SET completed_at = CURRENT_TIMESTAMP, devices_found = ? WHERE id = ?",
            params![devices_found as i32, scan_id],
        )?;
        Ok(())
    }
}

/// Summary of a network's historical data
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NetworkSummary {
    pub bssid: String,
    pub ssid: String,
    pub avg_signal_dbm: f64,
    pub avg_score: f64,
    pub times_seen: i64,
    pub last_signal_dbm: i32,
    pub last_score: i32,
}

/// Network data loaded from database for display
#[derive(Debug, Clone)]
pub struct LoadedNetwork {
    pub bssid: String,
    pub ssid: String,
    pub channel: u8,
    pub signal_dbm: i32,
    pub security: String,
    pub frequency_band: String,
    pub score: u8,
    pub last_seen: DateTime<Utc>,
}

/// Connection record from the database
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub id: i64,
    pub network_id: i64,
    pub connected_at: DateTime<Utc>,
    pub disconnected_at: Option<DateTime<Utc>>,
    pub local_ip: Option<String>,
    pub public_ip: Option<String>,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
}

/// Known network record from the database
#[derive(Debug, Clone)]
pub struct KnownNetwork {
    pub id: i64,
    pub ssid: String,
    pub last_connected_at: Option<DateTime<Utc>>,
    pub added_at: Option<DateTime<Utc>>,
    pub imported_at: DateTime<Utc>,
}

/// Device record from the database
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: i64,
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub custom_name: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub network_bssid: Option<String>,
}

/// Service record from the database
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    pub id: i64,
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub banner: Option<String>,
    pub detected_agent: Option<String>,
}

/// Parse a timestamp string from DuckDB
fn parse_timestamp(s: &str) -> DateTime<Utc> {
    // DuckDB returns timestamps in ISO 8601 format
    chrono::DateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| s.parse::<DateTime<Utc>>())
        .unwrap_or_else(|_| Utc::now())
}
