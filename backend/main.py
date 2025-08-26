#!/usr/bin/env python3
"""
🚀 Target-Centric Admin Dashboard - FastAPI Backend
Main application entry point for the Raspberry Pi hotspot control system
"""

import os
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import logging
from datetime import datetime, timedelta
import subprocess
import json
import sqlite3
from typing import List, Optional, Dict, Any
import asyncio
import threading
import time

# Import our modules
from models import *
from database import Database
from auth import Auth
from network_control import NetworkControl
from mitmproxy_controller import MitmProxyController
from device_monitor import DeviceMonitor
from rules_engine import RulesEngine
from system_monitor import SystemMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/backend.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# Global instances
db = None
auth = None
network_control = None
mitm_controller = None
device_monitor = None
rules_engine = None
system_monitor = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    global db, auth, network_control, mitm_controller, device_monitor, rules_engine, system_monitor
    
    # Startup
    logger.info("🚀 Starting Target-Centric Admin Dashboard...")
    
    # Initialize database
    db = Database()
    db.init_database()
    
    # Initialize auth
    auth = Auth(db)
    
    # Initialize network control
    network_control = NetworkControl()
    
    # Initialize mitmproxy controller
    mitm_controller = MitmProxyController()
    
    # Initialize device monitor
    device_monitor = DeviceMonitor(db, network_control)
    
    # Initialize rules engine
    rules_engine = RulesEngine(db, mitm_controller, network_control)
    
    # Initialize system monitor
    system_monitor = SystemMonitor()
    
    # Start background tasks
    asyncio.create_task(device_monitor.start_monitoring())
    asyncio.create_task(rules_engine.start_processing())
    asyncio.create_task(system_monitor.start_monitoring())
    
    logger.info("✅ Backend services initialized successfully")
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down backend services...")
    if device_monitor:
        await device_monitor.stop_monitoring()
    if rules_engine:
        await rules_engine.stop_processing()
    if system_monitor:
        await system_monitor.stop_monitoring()
    if mitm_controller:
        mitm_controller.stop()

# Create FastAPI app
app = FastAPI(
    title="Target-Centric Admin Dashboard",
    description="Mission control for Raspberry Pi hotspot with device-level network control",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency for authentication
async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT token and return admin user"""
    try:
        payload = auth.verify_token(credentials.credentials)
        return payload
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest):
    """Admin login endpoint"""
    try:
        token = auth.authenticate(login_data.username, login_data.password)
        return LoginResponse(access_token=token, token_type="bearer")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/change-password")
async def change_password(
    password_data: ChangePasswordRequest,
    current_admin: dict = Depends(get_current_admin)
):
    """Change admin password"""
    try:
        success = auth.change_password(password_data.current_password, password_data.new_password)
        if success:
            logger.info("Admin password changed successfully")
            return {"message": "Password changed successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to change password")
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/admin-info")
async def get_admin_info(current_admin: dict = Depends(get_current_admin)):
    """Get admin user information"""
    try:
        admin_info = auth.get_admin_info()
        if admin_info:
            return admin_info
        else:
            raise HTTPException(status_code=404, detail="Admin info not found")
    except Exception as e:
        logger.error(f"Error getting admin info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get admin info")

# ============================================================================
# DEVICE MANAGEMENT ENDPOINTS
# ============================================================================

@app.get("/devices", response_model=List[Device])
async def get_devices(current_admin: dict = Depends(get_current_admin)):
    """Get list of all connected devices"""
    try:
        devices = db.get_devices()
        return devices
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to get devices")

@app.post("/device/block")
async def block_device(
    request: DeviceActionRequest,
    current_admin: dict = Depends(get_current_admin)
):
    """Block a device from network access"""
    try:
        success = network_control.block_device(request.ip_address)
        if success:
            db.update_device_status(request.ip_address, "blocked")
            logger.info(f"Device {request.ip_address} blocked by admin")
            return {"message": f"Device {request.ip_address} blocked successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to block device")
    except Exception as e:
        logger.error(f"Error blocking device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/device/unblock")
async def unblock_device(
    request: DeviceActionRequest,
    current_admin: dict = Depends(get_current_admin)
):
    """Unblock a device"""
    try:
        success = network_control.unblock_device(request.ip_address)
        if success:
            db.update_device_status(request.ip_address, "active")
            logger.info(f"Device {request.ip_address} unblocked by admin")
            return {"message": f"Device {request.ip_address} unblocked successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to unblock device")
    except Exception as e:
        logger.error(f"Error unblocking device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/device/throttle")
async def throttle_device(
    request: ThrottleRequest,
    current_admin: dict = Depends(get_current_admin)
):
    """Throttle device bandwidth"""
    try:
        success = network_control.throttle_device(
            request.ip_address, 
            request.bandwidth_limit
        )
        if success:
            db.update_device_throttle(request.ip_address, request.bandwidth_limit)
            logger.info(f"Device {request.ip_address} throttled to {request.bandwidth_limit}")
            return {"message": f"Device {request.ip_address} throttled successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to throttle device")
    except Exception as e:
        logger.error(f"Error throttling device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/device/kick")
async def kick_device(
    request: DeviceActionRequest,
    current_admin: dict = Depends(get_current_admin)
):
    """Kick device from WiFi network"""
    try:
        success = network_control.kick_device(request.ip_address)
        if success:
            logger.info(f"Device {request.ip_address} kicked by admin")
            return {"message": f"Device {request.ip_address} kicked successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to kick device")
    except Exception as e:
        logger.error(f"Error kicking device: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# RULES MANAGEMENT ENDPOINTS
# ============================================================================

@app.get("/rules", response_model=List[Rule])
async def get_rules(current_admin: dict = Depends(get_current_admin)):
    """Get all filtering rules"""
    try:
        rules = db.get_rules()
        return rules
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to get rules")

@app.post("/rules/add", response_model=Rule)
async def add_rule(
    rule: RuleCreate,
    current_admin: dict = Depends(get_current_admin)
):
    """Add new filtering rule"""
    try:
        new_rule = db.add_rule(rule)
        rules_engine.reload_rules()
        logger.info(f"New rule added: {rule.name}")
        return new_rule
    except Exception as e:
        logger.error(f"Error adding rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rules/update/{rule_id}", response_model=Rule)
async def update_rule(
    rule_id: int,
    rule: RuleUpdate,
    current_admin: dict = Depends(get_current_admin)
):
    """Update existing rule"""
    try:
        updated_rule = db.update_rule(rule_id, rule)
        rules_engine.reload_rules()
        logger.info(f"Rule {rule_id} updated")
        return updated_rule
    except Exception as e:
        logger.error(f"Error updating rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/rules/delete/{rule_id}")
async def delete_rule(
    rule_id: int,
    current_admin: dict = Depends(get_current_admin)
):
    """Delete rule"""
    try:
        db.delete_rule(rule_id)
        rules_engine.reload_rules()
        logger.info(f"Rule {rule_id} deleted")
        return {"message": "Rule deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/rules/toggle/{rule_id}")
async def toggle_rule(
    rule_id: int,
    current_admin: dict = Depends(get_current_admin)
):
    """Toggle rule status ON/OFF"""
    try:
        rule = db.toggle_rule(rule_id)
        rules_engine.reload_rules()
        status_text = "enabled" if rule.status == "on" else "disabled"
        logger.info(f"Rule {rule_id} {status_text}")
        return {"message": f"Rule {status_text} successfully"}
    except Exception as e:
        logger.error(f"Error toggling rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# LOGS ENDPOINTS
# ============================================================================

@app.get("/logs/{ip_address}")
async def get_device_logs(
    ip_address: str,
    current_admin: dict = Depends(get_current_admin)
):
    """Get logs for specific device"""
    try:
        logs = db.get_device_logs(ip_address)
        return {"ip_address": ip_address, "logs": logs}
    except Exception as e:
        logger.error(f"Error getting logs for {ip_address}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get logs")

@app.get("/logs/{ip_address}/{date}")
async def get_device_logs_by_date(
    ip_address: str,
    date: str,
    current_admin: dict = Depends(get_current_admin)
):
    """Get logs for specific device and date"""
    try:
        logs = db.get_device_logs_by_date(ip_address, date)
        return {"ip_address": ip_address, "date": date, "logs": logs}
    except Exception as e:
        logger.error(f"Error getting logs for {ip_address} on {date}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get logs")

# ============================================================================
# SYSTEM STATUS ENDPOINTS
# ============================================================================

@app.get("/status", response_model=SystemStatus)
async def get_system_status(current_admin: dict = Depends(get_current_admin)):
    """Get overall system status"""
    try:
        if system_monitor:
            devices_count = len(db.get_devices())
            active_rules_count = len([r for r in db.get_rules() if r.status == "on"])
            status_data = system_monitor.get_system_status(devices_count, active_rules_count)
            return SystemStatus(**status_data)
        else:
            raise HTTPException(status_code=500, detail="System monitor not available")
    except Exception as e:
        logger.error(f"Error getting system status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system status")

@app.get("/stats")
async def get_system_stats(current_admin: dict = Depends(get_current_admin)):
    """Get system statistics"""
    try:
        stats = {
            "total_devices": len(db.get_devices()),
            "blocked_devices": len([d for d in db.get_devices() if d.status == "blocked"]),
            "throttled_devices": len([d for d in db.get_devices() if d.bandwidth_limit]),
            "total_rules": len(db.get_rules()),
            "active_rules": len([r for r in db.get_rules() if r.status == "on"]),
            "total_logs": db.get_total_logs_count()
        }
        return stats
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system stats")

@app.get("/performance", response_model=SystemPerformance)
async def get_system_performance(current_admin: dict = Depends(get_current_admin)):
    """Get detailed system performance metrics"""
    try:
        if system_monitor:
            performance_data = system_monitor.get_system_performance()
            return SystemPerformance(**performance_data)
        else:
            raise HTTPException(status_code=500, detail="System monitor not available")
    except Exception as e:
        logger.error(f"Error getting system performance: {e}")
        raise HTTPException(status_code=500, detail="Failed to get system performance")

# ============================================================================
# SYSTEM RESET ENDPOINT
# ============================================================================

@app.post("/reset-system")
async def reset_system(current_admin: dict = Depends(get_current_admin)):
    """Reset all system settings to factory defaults (Router Reset)"""
    try:
        logger.warning("System reset initiated by admin")
        
        # Stop all services
        if device_monitor:
            await device_monitor.stop_monitoring()
        if rules_engine:
            await rules_engine.stop_processing()
        if system_monitor:
            await system_monitor.stop_monitoring()
        if mitm_controller:
            mitm_controller.stop()
        
        # Reset database
        db.reset_database()
        
        # Reinitialize services
        if device_monitor:
            await device_monitor.start_monitoring()
        if rules_engine:
            await rules_engine.start_processing()
        if system_monitor:
            await system_monitor.start_monitoring()
        
        logger.info("System reset completed successfully")
        return {"message": "System reset completed successfully. Default credentials: admin/admin123"}
        
    except Exception as e:
        logger.error(f"Error during system reset: {e}")
        raise HTTPException(status_code=500, detail=f"System reset failed: {str(e)}")

# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    # Start the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
