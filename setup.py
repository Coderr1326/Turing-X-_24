"""
Setup script for Threat Intelligence Platform
Run this first to set up everything
"""

import os
import sys

def create_init_files():
    """Create __init__.py files in all package directories"""
    packages = ['config', 'core', 'collectors', 'analyzers', 'api', 'utils']
    
    for package in packages:
        init_file = os.path.join(package, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write(f'"""{package.capitalize()} package"""\n')
            print(f"✓ Created {init_file}")

def check_dependencies():
    """Check if required packages are installed"""
    required = ['requests', 'pandas', 'python-dotenv']
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print("\n❌ Missing dependencies:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nInstall with: pip install " + " ".join(missing))
        return False
    
    print("✓ All dependencies installed")
    return True

def create_env_file():
    """Create .env file if it doesn't exist"""
    if not os.path.exists('.env'):
        with open('.env', 'w') as f:
            f.write("""# API Keys (get free keys from these services)
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
ALIENVAULT_API_KEY=

# Database
DATABASE_PATH=data/threat_intel.db

# Thresholds
MALICIOUS_THRESHOLD=50
HIGH_CONFIDENCE_THRESHOLD=75
""")
        print("✓ Created .env file")
    else:
        print("✓ .env file exists")

def main():
    print("\n" + "="*70)
    print("🛡️  THREAT INTELLIGENCE PLATFORM SETUP")
    print("="*70 + "\n")
    
    print("1. Creating package structure...")
    create_init_files()
    
    print("\n2. Checking dependencies...")
    if not check_dependencies():
        print("\n❌ Setup incomplete. Install missing dependencies first.")
        return
    
    print("\n3. Creating environment file...")
    create_env_file()
    
    print("\n4. Initializing database...")
    from core.database import ThreatDatabase
    try:
        db = ThreatDatabase()
        print("✓ Database initialized")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return
    
    print("\n" + "="*70)
    print("✅ SETUP COMPLETE!")
    print("="*70)
    print("\nNext steps:")
    print("1. Edit .env file and add your API keys (optional)")
    print("2. Run: python main.py")
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()
