#!/usr/bin/env python3
"""
⚙️ Target-Centric Admin Dashboard - Configuration
Pi Zero W optimized settings
"""

import os
from typing import Dict, Any

# ============================================================================
# ENVIRONMENT VARIABLES
# ============================================================================

# Database Configuration
DATABASE_PATH = os.getenv("DATABASE_PATH", "hotspot_control.db")
DATABASE_TIMEOUT = int(os.getenv("DATABASE_TIMEOUT", "30"))

# Authentication Configuration
SECRET_KEY = os.getenv("SECRET_KEY", None)  # Will be auto-generated if not set
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # Change this!
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

# Network Configuration
WIFI_INTERFACE = os.getenv("WIFI_INTERFACE", "wlan0")
BRIDGE_INTERFACE = os.getenv("BRIDGE_INTERFACE", "br0")
DHCP_START = os.getenv("DHCP_START", "192.168.50.10")
DHCP_END = os.getenv("DHCP_END", "192.168.50.100")
GATEWAY_IP = os.getenv("GATEWAY_IP", "192.168.50.1")
MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", "10"))
ENABLE_QOS = os.getenv("ENABLE_QOS", "true").lower() == "true"

# MitmProxy Configuration
MITMPROXY_PORT = int(os.getenv("MITMPROXY_PORT", "8080"))
MITMPROXY_INTERFACE = os.getenv("MITMPROXY_INTERFACE", "0.0.0.0")
MAX_MITM_CONNECTIONS = int(os.getenv("MAX_MITM_CONNECTIONS", "20"))
ENABLE_SSL_INTERCEPTION = os.getenv("ENABLE_SSL_INTERCEPTION", "false").lower() == "true"

# Device Monitoring Configuration
DEVICE_SCAN_INTERVAL = int(os.getenv("DEVICE_SCAN_INTERVAL", "30"))  # seconds
MAX_DEVICES = int(os.getenv("MAX_DEVICES", "10"))
ENABLE_ARP_MONITORING = os.getenv("ENABLE_ARP_MONITORING", "true").lower() == "true"

# Rules Engine Configuration
RULES_PROCESSING_INTERVAL = int(os.getenv("RULES_PROCESSING_INTERVAL", "60"))  # seconds
MAX_RULES = int(os.getenv("MAX_RULES", "100"))
ENABLE_RULE_CACHING = os.getenv("ENABLE_RULE_CACHING", "true").lower() == "true"

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/backend.log")
LOG_MAX_SIZE = int(os.getenv("LOG_MAX_SIZE", "10485760"))  # 10MB
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

# Server Configuration
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
WORKERS = int(os.getenv("WORKERS", "1"))  # Single worker for Pi Zero W
RELOAD = os.getenv("RELOAD", "false").lower() == "true"

# CORS Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")

# ============================================================================
# PI ZERO W OPTIMIZATIONS
# ============================================================================

# Memory management
MAX_MEMORY_USAGE = int(os.getenv("MAX_MEMORY_USAGE", "400"))  # MB (leave 100MB free)
ENABLE_MEMORY_MONITORING = os.getenv("ENABLE_MEMORY_MONITORING", "true").lower() == "true"

# Database optimizations
DATABASE_CACHE_SIZE = int(os.getenv("DATABASE_CACHE_SIZE", "1000"))  # 1MB
DATABASE_MMAP_SIZE = int(os.getenv("DATABASE_MMAP_SIZE", "268435456"))  # 256MB

# Network optimizations
ENABLE_NETWORK_MONITORING = os.getenv("ENABLE_NETWORK_MONITORING", "true").lower() == "true"
NETWORK_MONITOR_INTERVAL = int(os.getenv("NETWORK_MONITOR_INTERVAL", "60"))  # seconds

# ============================================================================
# SECURITY SETTINGS
# ============================================================================

# Rate limiting
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "3"))
LOGIN_LOCKOUT_DURATION = int(os.getenv("LOGIN_LOCKOUT_DURATION", "600"))  # 10 minutes

# Session management
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour
ENABLE_SESSION_CLEANUP = os.getenv("ENABLE_SESSION_CLEANUP", "true").lower() == "true"

# ============================================================================
# CONFIGURATION VALIDATION
# ============================================================================

def validate_config() -> Dict[str, Any]:
    """Validate configuration and return any warnings"""
    warnings = []
    
    # Check for default admin password
    if ADMIN_PASSWORD == "admin123":
        warnings.append("⚠️ Using default admin password! Change ADMIN_PASSWORD environment variable.")
    
    # Check for auto-generated secret key
    if not SECRET_KEY:
        warnings.append("ℹ️ No SECRET_KEY provided, using auto-generated key.")
    
    # Check Pi Zero W specific settings
    if WORKERS > 1:
        warnings.append("⚠️ Multiple workers not recommended for Pi Zero W. Set WORKERS=1.")
    
    if MAX_MITM_CONNECTIONS > 30:
        warnings.append("⚠️ High MitmProxy connection limit may impact Pi Zero W performance.")
    
    if DATABASE_MMAP_SIZE > 268435456:  # 256MB
        warnings.append("⚠️ High database mmap size may cause memory issues on Pi Zero W.")
    
    return {
        'valid': True,
        'warnings': warnings
    }

def get_config_summary() -> Dict[str, Any]:
    """Get configuration summary for logging"""
    return {
        'database': {
            'path': DATABASE_PATH,
            'timeout': DATABASE_TIMEOUT,
            'cache_size': DATABASE_CACHE_SIZE,
            'mmap_size': DATABASE_MMAP_SIZE
        },
        'network': {
            'wifi_interface': WIFI_INTERFACE,
            'bridge_interface': BRIDGE_INTERFACE,
            'gateway_ip': GATEWAY_IP,
            'max_connections': MAX_CONNECTIONS,
            'qos_enabled': ENABLE_QOS
        },
        'mitmproxy': {
            'port': MITMPROXY_PORT,
            'max_connections': MAX_MITM_CONNECTIONS,
            'ssl_enabled': ENABLE_SSL_INTERCEPTION
        },
        'monitoring': {
            'device_scan_interval': DEVICE_SCAN_INTERVAL,
            'max_devices': MAX_DEVICES,
            'rules_processing_interval': RULES_PROCESSING_INTERVAL
        },
        'server': {
            'host': HOST,
            'port': PORT,
            'workers': WORKERS,
            'reload': RELOAD
        },
        'security': {
            'max_login_attempts': MAX_LOGIN_ATTEMPTS,
            'lockout_duration': LOGIN_LOCKOUT_DURATION,
            'session_timeout': SESSION_TIMEOUT
        }
    }

# ============================================================================
# ENVIRONMENT-SPECIFIC OVERRIDES
# ============================================================================

def apply_environment_overrides():
    """Apply environment-specific configuration overrides"""
    environment = os.getenv("ENVIRONMENT", "production").lower()
    
    if environment == "development":
        # Development settings
        global LOG_LEVEL, RELOAD, ENABLE_MEMORY_MONITORING
        LOG_LEVEL = "DEBUG"
        RELOAD = True
        ENABLE_MEMORY_MONITORING = False
        
    elif environment == "testing":
        # Testing settings
        global DATABASE_PATH, LOG_LEVEL
        DATABASE_PATH = "test_hotspot_control.db"
        LOG_LEVEL = "WARNING"
        
    # Production uses default settings (optimized for Pi Zero W)

# Apply overrides on import
apply_environment_overrides()
