#!/usr/bin/env python3
"""
🎯 Target-Centric Admin Dashboard - Data Models
Optimized for Raspberry Pi Zero W with lightweight structures
"""

from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

# ============================================================================
# ENUMS
# ============================================================================

class DeviceStatus(str, Enum):
    """Device connection status"""
    ACTIVE = "active"
    BLOCKED = "blocked"
    THROTTLED = "throttled"
    DISCONNECTED = "disconnected"

class RuleAction(str, Enum):
    """Rule action types"""
    BLOCK = "block"
    REDIRECT = "redirect"
    THROTTLE = "throttle"
    MODIFY = "modify"
    ALERT = "alert"

class RuleStatus(str, Enum):
    """Rule status"""
    ON = "on"
    OFF = "off"

class LogLevel(str, Enum):
    """Log levels for Pi Zero W optimization"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"

# ============================================================================
# AUTHENTICATION MODELS
# ============================================================================

class LoginRequest(BaseModel):
    """Admin login request"""
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=100)

class LoginResponse(BaseModel):
    """Admin login response"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600  # 1 hour

class ChangePasswordRequest(BaseModel):
    """Change admin password request"""
    current_password: str = Field(..., min_length=1, max_length=100, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=100, description="New password (min 8 chars)")
    confirm_password: str = Field(..., min_length=1, max_length=100, description="Confirm new password")
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('new_password')
    def validate_new_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one number')
        return v

# ============================================================================
# DEVICE MODELS
# ============================================================================

class Device(BaseModel):
    """Connected device information"""
    ip_address: str = Field(..., description="Device IP address")
    mac_address: str = Field(..., description="Device MAC address")
    hostname: Optional[str] = Field(None, description="Device hostname")
    connected_since: datetime = Field(default_factory=datetime.now)
    status: DeviceStatus = Field(default=DeviceStatus.ACTIVE)
    bandwidth_limit: Optional[str] = Field(None, description="Bandwidth limit if throttled")
    data_usage: Optional[int] = Field(None, description="Data usage in bytes")
    last_seen: datetime = Field(default_factory=datetime.now)
    
    class Config:
        # Optimize for Pi Zero W - minimize memory usage
        json_encoders = {datetime: lambda v: v.isoformat()}
        validate_assignment = True

class DeviceActionRequest(BaseModel):
    """Generic device action request"""
    ip_address: str = Field(..., description="Target device IP")
    reason: Optional[str] = Field(None, description="Action reason")

class ThrottleRequest(BaseModel):
    """Device throttling request"""
    ip_address: str = Field(..., description="Target device IP")
    bandwidth_limit: str = Field(..., description="Bandwidth limit (e.g., '1Mbps', '500Kbps')")
    duration: Optional[int] = Field(None, description="Duration in minutes (0 = permanent)")

# ============================================================================
# RULES MODELS
# ============================================================================

class RuleCreate(BaseModel):
    """Create new filtering rule"""
    name: str = Field(..., min_length=1, max_length=100, description="Rule name")
    pattern: str = Field(..., min_length=1, max_length=500, description="Pattern to match")
    action: RuleAction = Field(..., description="Action to take")
    tags: List[str] = Field(default=[], description="Rule tags for organization")
    applied_to: str = Field(default="all", description="Target: 'all' or specific IP")
    priority: int = Field(default=100, ge=1, le=1000, description="Rule priority (lower = higher)")
    description: Optional[str] = Field(None, max_length=500, description="Rule description")

class RuleUpdate(BaseModel):
    """Update existing rule"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    pattern: Optional[str] = Field(None, min_length=1, max_length=500)
    action: Optional[RuleAction] = None
    tags: Optional[List[str]] = None
    applied_to: Optional[str] = None
    priority: Optional[int] = Field(None, ge=1, le=1000)
    description: Optional[str] = Field(None, max_length=500)
    status: Optional[RuleStatus] = None

class Rule(BaseModel):
    """Complete rule information"""
    id: int = Field(..., description="Rule ID")
    name: str = Field(..., description="Rule name")
    pattern: str = Field(..., description="Pattern to match")
    action: RuleAction = Field(..., description="Action to take")
    tags: List[str] = Field(default=[], description="Rule tags")
    applied_to: str = Field(..., description="Target devices")
    priority: int = Field(..., description="Rule priority")
    status: RuleStatus = Field(..., description="Rule status")
    description: Optional[str] = Field(None, description="Rule description")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    hit_count: int = Field(default=0, description="Number of times rule was triggered")
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

# ============================================================================
# LOGGING MODELS
# ============================================================================

class LogEntry(BaseModel):
    """Log entry for device activity"""
    timestamp: datetime = Field(default_factory=datetime.now)
    level: LogLevel = Field(default=LogLevel.INFO)
    message: str = Field(..., max_length=1000)
    ip_address: str = Field(..., description="Source IP address")
    url: Optional[str] = Field(None, description="Accessed URL")
    user_agent: Optional[str] = Field(None, description="User agent string")
    data_size: Optional[int] = Field(None, description="Data size in bytes")
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

class DeviceLogs(BaseModel):
    """Device logs response"""
    ip_address: str
    logs: List[LogEntry]
    total_count: int
    date_range: Optional[Dict[str, str]] = None

# ============================================================================
# SYSTEM MODELS (Pi Zero W specific)
# ============================================================================

class SystemStatus(BaseModel):
    """System status for Pi Zero W"""
    system: str = "online"
    uptime: float = Field(..., description="System uptime in seconds")
    cpu_usage: float = Field(..., ge=0, le=100, description="CPU usage percentage")
    memory_usage: float = Field(..., ge=0, le=100, description="Memory usage percentage")
    temperature: float = Field(..., description="CPU temperature in Celsius")
    disk_usage: float = Field(..., ge=0, le=100, description="Disk usage percentage")
    wifi_connected_devices: int = Field(..., ge=0, description="Number of connected devices")
    active_rules: int = Field(..., ge=0, description="Number of active rules")
    last_update: datetime = Field(default_factory=datetime.now)
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

class SystemPerformance(BaseModel):
    """Performance metrics for Pi Zero W"""
    cpu_frequency: float = Field(..., description="Current CPU frequency in MHz")
    memory_available: int = Field(..., description="Available memory in MB")
    memory_total: int = Field(..., description="Total memory in MB")
    swap_usage: float = Field(..., ge=0, le=100, description="Swap usage percentage")
    network_rx_bytes: int = Field(..., description="Received bytes")
    network_tx_bytes: int = Field(..., description="Transmitted bytes")
    load_average: List[float] = Field(..., description="Load averages (1, 5, 15 min)")
    
    @validator('load_average')
    def validate_load_average(cls, v):
        if len(v) != 3:
            raise ValueError('Load average must have exactly 3 values')
        return v

# ============================================================================
# NOTIFICATION MODELS
# ============================================================================

class Notification(BaseModel):
    """System notification"""
    id: int = Field(..., description="Notification ID")
    type: str = Field(..., description="Notification type")
    title: str = Field(..., max_length=200, description="Notification title")
    message: str = Field(..., max_length=1000, description="Notification message")
    level: LogLevel = Field(default=LogLevel.INFO)
    timestamp: datetime = Field(default_factory=datetime.now)
    read: bool = Field(default=False, description="Whether notification has been read")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional notification data")
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

# ============================================================================
# RESPONSE MODELS
# ============================================================================

class ApiResponse(BaseModel):
    """Generic API response"""
    success: bool = Field(..., description="Operation success status")
    message: str = Field(..., description="Response message")
    data: Optional[Any] = Field(None, description="Response data")
    timestamp: datetime = Field(default_factory=datetime.now)
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}

class PaginatedResponse(BaseModel):
    """Paginated response for large datasets"""
    items: List[Any] = Field(..., description="List of items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., ge=1, description="Current page number")
    per_page: int = Field(..., ge=1, le=100, description="Items per page")
    pages: int = Field(..., description="Total number of pages")
    
    @validator('pages')
    def calculate_pages(cls, v, values):
        if 'total' in values and 'per_page' in values:
            return (values['total'] + values['per_page'] - 1) // values['per_page']
        return v
