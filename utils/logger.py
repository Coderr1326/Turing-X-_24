"""
Logging Utility
Provides colored console output for better readability
"""

from datetime import datetime
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False

def log_info(message):
    """Log informational message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if COLORS_AVAILABLE:
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {timestamp} - {message}")
    else:
        print(f"[INFO] {timestamp} - {message}")

def log_success(message):
    """Log success message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if COLORS_AVAILABLE:
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {timestamp} - {message}")
    else:
        print(f"[SUCCESS] {timestamp} - {message}")

def log_warning(message):
    """Log warning message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if COLORS_AVAILABLE:
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {timestamp} - {message}")
    else:
        print(f"[WARNING] {timestamp} - {message}")

def log_error(message):
    """Log error message"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if COLORS_AVAILABLE:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {timestamp} - {message}")
    else:
        print(f"[ERROR] {timestamp} - {message}")

def log_header(message):
    """Log section header"""
    if COLORS_AVAILABLE:
        print(f"\n{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{message.center(70)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*70}{Style.RESET_ALL}\n")
    else:
        print(f"\n{'='*70}")
        print(f"{message.center(70)}")
        print(f"{'='*70}\n")
