"""
Query API
Provides search and analysis functions for threat intelligence
"""

import sqlite3
import pandas as pd
from config.config import DATABASE_PATH
from utils.logger import log_info

class ThreatQueryAPI:
    """API for querying threat intelligence database"""
    
    def __init__(self, db_path=DATABASE_PATH):
        self.db_path = db_path
    
    def search_ip(self, ip_address):
        """Search for complete threat intelligence on specific IP"""
        conn = sqlite3.connect(self.db_path)
        
        query = """
            SELECT 
                ti.*,
                GROUP_CONCAT(DISTINCT tc.category) as categories,
                GROUP_CONCAT(DISTINCT li.link_value) as linked_infrastructure
            FROM threat_indicators ti
            LEFT JOIN threat_categories tc ON ti.id = tc.threat_indicator_id
            LEFT JOIN linked_infrastructure li ON ti.id = li.threat_indicator_id
            WHERE ti.ip_address = ?
            GROUP BY ti.id
        """
        
        df = pd.read_sql(query, conn, params=(ip_address,))
        conn.close()
        
        return df
    
    def get_all_threats(self, limit=100):
        """Get all threat indicators"""
        conn = sqlite3.connect(self.db_path)
        
        query = f"""
            SELECT 
                ip_address,
                is_malicious,
                confidence_score,
                threat_level,
                country_name,
                city,
                source_name,
                last_seen,
                GROUP_CONCAT(DISTINCT tc.category) as categories
            FROM threat_indicators ti
            LEFT JOIN threat_categories tc ON ti.id = tc.threat_indicator_id
            GROUP BY ti.ip_address
            ORDER BY ti.last_seen DESC
            LIMIT {limit}
        """
        
        df = pd.read_sql(query, conn)
        conn.close()
        
        return df
    
    def get_malicious_ips(self, limit=50):
        """Get top malicious IPs by confidence score"""
        conn = sqlite3.connect(self.db_path)
        
        query = f"""
            SELECT 
                ip_address,
                confidence_score,
                threat_level,
                country_name,
                asn_organization,
                source_name,
                last_seen,
                GROUP_CONCAT(DISTINCT tc.category) as categories
            FROM threat_indicators ti
            LEFT JOIN threat_categories tc ON ti.id = tc.threat_indicator_id
            WHERE ti.is_malicious = 1
            GROUP BY ti.ip_address
            ORDER BY ti.confidence_score DESC
            LIMIT {limit}
        """
        
        df = pd.read_sql(query, conn)
        conn.close()
        
        return df
    
    def get_threats_by_country(self, country_code):
        """Get all threats from specific country"""
        conn = sqlite3.connect(self.db_path)
        
        query = """
            SELECT 
                ip_address,
                city,
                confidence_score,
                threat_level,
                GROUP_CONCAT(DISTINCT tc.category) as categories
            FROM threat_indicators ti
            LEFT JOIN threat_categories tc ON ti.id = tc.threat_indicator_id
            WHERE ti.country_code = ? AND ti.is_malicious = 1
            GROUP BY ti.ip_address
            ORDER BY ti.confidence_score DESC
        """
        
        df = pd.read_sql(query, conn, params=(country_code,))
        conn.close()
        
        return df
    
    def get_threats_by_asn(self, asn):
        """Get all threats from specific ASN"""
        conn = sqlite3.connect(self.db_path)
        
        query = """
            SELECT 
                ip_address,
                confidence_score,
                threat_level,
                country_name,
                GROUP_CONCAT(DISTINCT tc.category) as categories
            FROM threat_indicators ti
            LEFT JOIN threat_categories tc ON ti.id = tc.threat_indicator_id
            WHERE ti.asn = ? AND ti.is_malicious = 1
            GROUP BY ti.ip_address
            ORDER BY ti.confidence_score DESC
        """
        
        df = pd.read_sql(query, conn, params=(asn,))
        conn.close()
        
        return df
    
    def get_statistics(self):
        """Get comprehensive database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total indicators
        cursor.execute("SELECT COUNT(*) FROM threat_indicators")
        stats['total_indicators'] = cursor.fetchone()[0]
        
        # Malicious count
        cursor.execute("SELECT COUNT(*) FROM threat_indicators WHERE is_malicious = 1")
        stats['malicious_count'] = cursor.fetchone()[0]
        
        # Benign count
        cursor.execute("SELECT COUNT(*) FROM threat_indicators WHERE is_malicious = 0")
        stats['benign_count'] = cursor.fetchone()[0]
        
        # Top countries
        cursor.execute("""
            SELECT country_name, COUNT(*) as count 
            FROM threat_indicators 
            WHERE is_malicious = 1 AND country_name IS NOT NULL
            GROUP BY country_name 
            ORDER BY count DESC 
            LIMIT 10
        """)
        stats['top_countries'] = cursor.fetchall()
        
        # Top categories
        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM threat_categories tc
            JOIN threat_indicators ti ON tc.threat_indicator_id = ti.id
            WHERE ti.is_malicious = 1
            GROUP BY category
            ORDER BY count DESC
            LIMIT 10
        """)
        stats['top_categories'] = cursor.fetchall()
        
        # Sources breakdown
        cursor.execute("""
            SELECT source_name, COUNT(*) as count
            FROM threat_indicators
            GROUP BY source_name
            ORDER BY count DESC
        """)
        stats['sources'] = cursor.fetchall()
        
        # Threat levels distribution
        cursor.execute("""
            SELECT threat_level, COUNT(*) as count
            FROM threat_indicators
            WHERE is_malicious = 1
            GROUP BY threat_level
            ORDER BY count DESC
        """)
        stats['threat_levels'] = cursor.fetchall()
        
        conn.close()
        return stats
    
    def search_by_category(self, category, limit=50):
        """Search threats by category"""
        conn = sqlite3.connect(self.db_path)
        
        query = f"""
            SELECT DISTINCT
                ti.ip_address,
                ti.confidence_score,
                ti.threat_level,
                ti.country_name,
                ti.asn_organization
            FROM threat_indicators ti
            JOIN threat_categories tc ON ti.id = tc.threat_indicator_id
            WHERE tc.category = ? AND ti.is_malicious = 1
            ORDER BY ti.confidence_score DESC
            LIMIT {limit}
        """
        
        df = pd.read_sql(query, conn, params=(category,))
        conn.close()
        
        return df
