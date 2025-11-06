#!/usr/bin/env python3
"""
Threat Intelligence Platform - Main Control Program
Complete implementation with all features
"""

import sys
import os
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import ThreatDatabase
from core.normalizer import ThreatDataNormalizer
from core.reputation_scorer import ReputationScorer
from core.correlator import ThreatCorrelator

from collectors.free_sources import IPApiCollector, IPQualityScoreCollector
from collectors.abuseipdb_collector import AbuseIPDBCollector
from collectors.virustotal_collector import VirusTotalCollector

from api.query_api import ThreatQueryAPI

from utils.logger import log_header, log_info, log_success, log_warning, log_error
from utils.validators import is_valid_ip, sanitize_ip

from config.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

def print_menu():
    """Display main menu"""
    log_header("🛡️  THREAT INTELLIGENCE PLATFORM")
    print("1.  Initialize Database")
    print("2.  Collect Threat Data (Single IP)")
    print("3.  Collect Threat Data (Multiple IPs)")
    print("4.  Search IP")
    print("5.  Show All Threats")
    print("6.  Show Top Malicious IPs")
    print("7.  Search by Country")
    print("8.  Search by Category")
    print("9.  Find Correlations")
    print("10. Show Statistics")
    print("11. Calculate Reputation Score")
    print("12. Exit")
    print("\n" + "="*70 + "\n")

def initialize_database():
    """Initialize the database"""
    try:
        log_info("Initializing database...")
        db = ThreatDatabase()
        log_success("Database initialized successfully!")
        return db
    except Exception as e:
        log_error(f"Database initialization failed: {e}")
        return None

def collect_single_ip(ip_address):
    """Collect threat data for single IP from all available sources"""
    ip_address = sanitize_ip(ip_address)
    
    if not ip_address:
        log_error("Invalid IP address")
        return
    
    log_info(f"Starting collection for: {ip_address}")
    
    db = ThreatDatabase()
    normalizer = ThreatDataNormalizer()
    
    collected_data = []
    
    # Collect from free sources first (geolocation)
    log_info("\n📍 Collecting geolocation data...")
    ipapi_collector = IPApiCollector()
    geo_data = ipapi_collector.collect(ip_address)
    if geo_data:
        collected_data.append(geo_data)
    
    # Collect from AbuseIPDB if API key available
    if ABUSEIPDB_API_KEY:
        log_info("\n🔍 Checking AbuseIPDB...")
        abuseipdb_collector = AbuseIPDBCollector(ABUSEIPDB_API_KEY)
        abuse_data = abuseipdb_collector.collect(ip_address)
        if abuse_data:
            collected_data.append(abuse_data)
    else:
        log_warning("AbuseIPDB API key not configured - skipping")
    
    # Collect from VirusTotal if API key available
    if VIRUSTOTAL_API_KEY:
        log_info("\n🦠 Checking VirusTotal...")
        vt_collector = VirusTotalCollector(VIRUSTOTAL_API_KEY)
        vt_data = vt_collector.collect(ip_address)
        if vt_data:
            collected_data.append(vt_data)
    else:
        log_warning("VirusTotal API key not configured - skipping")
    
    # Insert all collected data into database
    if collected_data:
        log_info(f"\n💾 Saving {len(collected_data)} records to database...")
        for data in collected_data:
            try:
                db.insert_threat_indicator(data)
            except Exception as e:
                log_error(f"Failed to insert data from {data.get('source_name')}: {e}")
        
        log_success(f"✓ Collection complete for {ip_address}")
        log_info(f"Collected from {len(collected_data)} source(s)")
    else:
        log_warning("No data collected")

def collect_multiple_ips(ip_list):
    """Collect threat data for multiple IPs"""
    log_info(f"Starting batch collection for {len(ip_list)} IPs...")
    
    for idx, ip in enumerate(ip_list, 1):
        print(f"\n{'='*70}")
        log_info(f"Processing IP {idx}/{len(ip_list)}: {ip}")
        print('='*70)
        collect_single_ip(ip)
    
    log_success(f"\n✓ Batch collection complete! Processed {len(ip_list)} IPs")

def search_ip_info(ip_address):
    """Search and display complete information about an IP"""
    ip_address = sanitize_ip(ip_address)
    
    if not ip_address:
        log_error("Invalid IP address")
        return
    
    api = ThreatQueryAPI()
    df = api.search_ip(ip_address)
    
    if df.empty:
        log_warning(f"No data found for {ip_address}")
        return
    
    log_header(f"🔍 THREAT INTELLIGENCE REPORT: {ip_address}")
    
    for _, row in df.iterrows():
        print(f"\n{'─'*70}")
        print(f"Source: {row['source_name']}")
        print(f"{'─'*70}")
        print(f"Malicious: {'YES' if row['is_malicious'] else 'NO'}")
        print(f"Confidence Score: {row['confidence_score']}")
        print(f"Threat Level: {row['threat_level']}")
        print(f"Categories: {row['categories'] if row['categories'] else 'None'}")
        print(f"\n📍 Location:")
        print(f"  Country: {row['country_name']} ({row['country_code']})")
        print(f"  City: {row['city']}")
        print(f"  Coordinates: ({row['latitude']}, {row['longitude']})")
        print(f"\n🌐 Network:")
        print(f"  ASN: {row['asn']}")
        print(f"  Organization: {row['asn_organization']}")
        print(f"  ISP: {row['isp']}")
        print(f"\n📅 Timestamps:")
        print(f"  First Seen: {row['first_seen']}")
        print(f"  Last Seen: {row['last_seen']}")
        
        if row['linked_infrastructure']:
            print(f"\n🔗 Linked Infrastructure:")
            print(f"  {row['linked_infrastructure']}")

def show_statistics():
    """Display comprehensive statistics"""
    api = ThreatQueryAPI()
    stats = api.get_statistics()
    
    log_header("📊 THREAT INTELLIGENCE STATISTICS")
    
    print(f"\n📈 Overview:")
    print(f"  Total Indicators: {stats['total_indicators']}")
    print(f"  Malicious: {stats['malicious_count']}")
    print(f"  Benign: {stats['benign_count']}")
    
    if stats['malicious_count'] > 0:
        malicious_percent = (stats['malicious_count'] / stats['total_indicators']) * 100
        print(f"  Malicious Rate: {malicious_percent:.1f}%")
    
    if stats['top_countries']:
        print(f"\n🌍 Top Threat Countries:")
        for country, count in stats['top_countries']:
            print(f"  • {country}: {count} threats")
    
    if stats['top_categories']:
        print(f"\n🏷️  Top Threat Categories:")
        for category, count in stats['top_categories']:
            print(f"  • {category}: {count} incidents")
    
    if stats['sources']:
        print(f"\n📡 Data Sources:")
        for source, count in stats['sources']:
            print(f"  • {source}: {count} records")
    
    if stats['threat_levels']:
        print(f"\n⚠️  Threat Levels Distribution:")
        for level, count in stats['threat_levels']:
            print(f"  • {level}: {count}")

def find_correlations_menu():
    """Correlation analysis menu"""
    print("\n" + "="*70)
    print("🔗 CORRELATION ANALYSIS")
    print("="*70)
    print("\n1. Find threats by ASN")
    print("2. Find threats by Country")
    print("3. Find multi-source reports for IP")
    print("4. Identify threat clusters")
    print("5. Back to main menu")
    
    choice = input("\n👉 Select option (1-5): ").strip()
    
    correlator = ThreatCorrelator()
    
    if choice == '1':
        asn = input("Enter ASN number: ").strip()
        try:
            asn = int(asn)
            results = correlator.correlate_by_asn(asn)
            if results:
                print(f"\n📊 Found {len(results)} threats in ASN {asn}:")
                for ip, score, level, cats in results:
                    print(f"  • {ip} - Score: {score}, Level: {level}, Categories: {cats}")
            else:
                log_warning(f"No threats found for ASN {asn}")
        except ValueError:
            log_error("Invalid ASN number")
    
    elif choice == '2':
        country = input("Enter country code (e.g., US, CN, RU): ").strip().upper()
        results = correlator.correlate_by_country(country)
        if results:
            print(f"\n📊 Found {len(results)} recent threats from {country}:")
            for ip, city, score, cats, last_seen in results:
                print(f"  • {ip} ({city}) - Score: {score}, Last seen: {last_seen}")
        else:
            log_warning(f"No recent threats found from {country}")
    
    elif choice == '3':
        ip = input("Enter IP address: ").strip()
        results = correlator.correlate_multi_source(ip)
        if results:
            print(f"\n📊 {ip} reported by {len(results)} source(s):")
            for source, score, level, cats in results:
                print(f"  • {source}: Score {score}, Level: {level}, Categories: {cats}")
        else:
            log_warning(f"No multi-source data for {ip}")
    
    elif choice == '4':
        results = correlator.identify_threat_clusters()
        if results:
            print(f"\n📊 Identified {len(results)} threat clusters:")
            for asn, org, cat, count, ips in results:
                print(f"\n  Cluster: ASN {asn} ({org}) - Category: {cat}")
                print(f"  Threat Count: {count}")
                print(f"  IPs: {ips[:100]}{'...' if len(ips) > 100 else ''}")
        else:
            log_warning("No threat clusters found")

def calculate_reputation_menu():
    """Calculate comprehensive reputation score"""
    ip = input("\nEnter IP address: ").strip()
    
    api = ThreatQueryAPI()
    df = api.search_ip(ip)
    
    if df.empty:
        log_warning(f"No data found for {ip}. Collect data first.")
        return
    
    # Get data from first record
    row = df.iloc[0]
    
    scorer = ReputationScorer()
    result = scorer.calculate_comprehensive_reputation(
        confidence_score=row['confidence_score'],
        source_reliability=row['source_reliability'],
        last_seen=row['last_seen'],
        incident_count=row['historical_incidents'],
        categories=row['categories'].split(',') if row['categories'] else [],
        source_count=len(df)
    )
    
    log_header(f"📊 REPUTATION SCORE: {ip}")
    print(f"\n🎯 Final Score: {result['final_score']}/100")
    print(f"\n📊 Score Breakdown:")
    print(f"  Base Score: {result['base_score']}")
    print(f"  Time Adjusted: {result['time_adjusted']}")
    print(f"  Frequency Score: {result['frequency_score']}")
    print(f"  Category Bonus: {result['category_bonus']}")
    print(f"  Correlation Bonus: {result['correlation_bonus']}")

def main():
    """Main program loop"""
    # Initialize database on startup
    db = initialize_database()
    if not db:
        log_error("Cannot continue without database. Exiting.")
        return
    
    api = ThreatQueryAPI()
    
    while True:
        try:
            print_menu()
            choice = input("👉 Select an option (1-12): ").strip()
            
            if choice == '1':
                initialize_database()
            
            elif choice == '2':
                ip = input("\n🔍 Enter IP address: ").strip()
                if is_valid_ip(ip):
                    collect_single_ip(ip)
                else:
                    log_error("Invalid IP address format")
            
            elif choice == '3':
                ips_input = input("\n🔍 Enter IP addresses (comma-separated): ").strip()
                ips = [ip.strip() for ip in ips_input.split(',') if is_valid_ip(ip.strip())]
                if ips:
                    collect_multiple_ips(ips)
                else:
                    log_error("No valid IP addresses provided")
            
            elif choice == '4':
                ip = input("\n🔍 Enter IP address: ").strip()
                if is_valid_ip(ip):
                    search_ip_info(ip)
                else:
                    log_error("Invalid IP address format")
            
            elif choice == '5':
                limit = input("\n🔢 How many to show? (default 50): ").strip()
                limit = int(limit) if limit.isdigit() else 50
                df = api.get_all_threats(limit)
                if not df.empty:
                    log_header(f"📋 ALL THREATS (Last {limit})")
                    print(df.to_string(index=False))
                else:
                    log_warning("No data yet. Collect some data first!")
            
            elif choice == '6':
                limit = input("\n🔢 How many top threats? (default 20): ").strip()
                limit = int(limit) if limit.isdigit() else 20
                df = api.get_malicious_ips(limit)
                if not df.empty:
                    log_header(f"⚠️  TOP {limit} MALICIOUS IPs")
                    print(df.to_string(index=False))
                else:
                    log_warning("No malicious IPs found yet!")
            
            elif choice == '7':
                country = input("\n🌍 Enter country code (e.g., US, CN, RU): ").strip().upper()
                df = api.get_threats_by_country(country)
                if not df.empty:
                    log_header(f"🌍 THREATS FROM {country}")
                    print(df.to_string(index=False))
                else:
                    log_warning(f"No threats found from {country}")
            
            elif choice == '8':
                print("\nCommon categories: botnet, malware, phishing, c2_server, scanner, spam")
                category = input("Enter category: ").strip().lower()
                df = api.search_by_category(category)
                if not df.empty:
                    log_header(f"🏷️  THREATS IN CATEGORY: {category}")
                    print(df.to_string(index=False))
                else:
                    log_warning(f"No threats found in category '{category}'")
            
            elif choice == '9':
                find_correlations_menu()
            
            elif choice == '10':
                show_statistics()
            
            elif choice == '11':
                calculate_reputation_menu()
            
            elif choice == '12':
                log_success("\n👋 Thank you for using Threat Intelligence Platform!")
                sys.exit(0)
            
            else:
                log_error("Invalid choice. Please select 1-12.")
            
            input("\n⏎ Press Enter to continue...")
        
        except KeyboardInterrupt:
            log_success("\n\n👋 Interrupted. Goodbye!")
            sys.exit(0)
        except Exception as e:
            log_error(f"Unexpected error: {e}")
            input("\n⏎ Press Enter to continue...")

if __name__ == "__main__":
    main()
