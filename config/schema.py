"""
Unified Threat Intelligence Schema
Based on industry best practices and STIX/TAXII standards
"""

SCHEMA_VERSION = "1.0.0"

# Complete database schema
DATABASE_SCHEMA = {
    "threat_indicators": """
        CREATE TABLE IF NOT EXISTS threat_indicators (
            -- Primary Identifier
            id TEXT PRIMARY KEY,
            
            -- Indicator Information
            ip_address TEXT NOT NULL,
            indicator_type TEXT DEFAULT 'ip_address',
            
            -- Classification[source:96]
            is_malicious INTEGER DEFAULT 0,
            threat_level TEXT,
            confidence_score REAL DEFAULT 0.0,
            overall_reputation_score INTEGER DEFAULT 0,
            false_positive_likelihood REAL DEFAULT 0.0,
            
            -- Geolocation
            country_code TEXT,
            country_name TEXT,
            region TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            postal_code TEXT,
            timezone TEXT,
            
            -- Network Information
            asn INTEGER,
            asn_name TEXT,
            asn_organization TEXT,
            isp TEXT,
            connection_type TEXT,
            network_range TEXT,
            
            -- Source Metadata
            source_name TEXT NOT NULL,
            source_type TEXT,
            source_reliability TEXT,
            source_url TEXT,
            collection_method TEXT,
            feed_weight REAL DEFAULT 0.5,
            
            -- Reputation
            historical_incidents INTEGER DEFAULT 0,
            report_count INTEGER DEFAULT 0,
            
            -- Timestamps
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            timestamp_collected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            timestamp_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            
            -- Enrichment
            whois_registrar TEXT,
            whois_registrant TEXT,
            reverse_dns TEXT,
            
            -- Metadata
            tags TEXT,
            tlp_marking TEXT DEFAULT 'TLP_WHITE',
            
            -- Indexes
            UNIQUE(ip_address, source_name)
        )
    """,
    
    "threat_categories": """
        CREATE TABLE IF NOT EXISTS threat_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_indicator_id TEXT NOT NULL,
            category TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            FOREIGN KEY (threat_indicator_id) REFERENCES threat_indicators(id) ON DELETE CASCADE
        )
    """,
    
    "linked_infrastructure": """
        CREATE TABLE IF NOT EXISTS linked_infrastructure (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_indicator_id TEXT NOT NULL,
            link_type TEXT NOT NULL,
            link_value TEXT NOT NULL,
            relationship TEXT,
            confidence REAL DEFAULT 1.0,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (threat_indicator_id) REFERENCES threat_indicators(id) ON DELETE CASCADE
        )
    """,
    
    "attack_context": """
        CREATE TABLE IF NOT EXISTS attack_context (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_indicator_id TEXT NOT NULL,
            mitre_attack_id TEXT,
            malware_family TEXT,
            campaign_name TEXT,
            threat_actor TEXT,
            cve_id TEXT,
            FOREIGN KEY (threat_indicator_id) REFERENCES threat_indicators(id) ON DELETE CASCADE
        )
    """,
    
    "reputation_history": """
        CREATE TABLE IF NOT EXISTS reputation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_indicator_id TEXT NOT NULL,
            score INTEGER NOT NULL,
            source_name TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (threat_indicator_id) REFERENCES threat_indicators(id) ON DELETE CASCADE
        )
    """,
    
    "correlation_events": """
        CREATE TABLE IF NOT EXISTS correlation_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            related_indicators TEXT NOT NULL,
            correlation_score REAL,
            description TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
}

# Index definitions for performance
INDEX_DEFINITIONS = [
    "CREATE INDEX IF NOT EXISTS idx_ip ON threat_indicators(ip_address)",
    "CREATE INDEX IF NOT EXISTS idx_malicious ON threat_indicators(is_malicious, is_active)",
    "CREATE INDEX IF NOT EXISTS idx_source ON threat_indicators(source_name)",
    "CREATE INDEX IF NOT EXISTS idx_last_seen ON threat_indicators(last_seen DESC)",
    "CREATE INDEX IF NOT EXISTS idx_confidence ON threat_indicators(confidence_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_country ON threat_indicators(country_code)",
    "CREATE INDEX IF NOT EXISTS idx_asn ON threat_indicators(asn)",
    "CREATE INDEX IF NOT EXISTS idx_category ON threat_categories(category)",
    "CREATE INDEX IF NOT EXISTS idx_link_value ON linked_infrastructure(link_value)",
    "CREATE INDEX IF NOT EXISTS idx_link_type ON linked_infrastructure(link_type)"
]
