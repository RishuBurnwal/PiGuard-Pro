#!/usr/bin/env python3
"""
📱 Target-Centric Admin Dashboard - Device Monitor
Device tracking and monitoring for Pi Zero W
"""

import os
import logging
import asyncio
import time
import subprocess
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

class DeviceMonitor:
    """Monitor connected devices and their activities"""
    
    def __init__(self, database, network_control):
        self.db = database
        self.network_control = network_control
        self.monitoring = False
        self.monitor_task = None
        self._lock = threading.Lock()
        
        # Pi Zero W specific settings
        self.scan_interval = int(os.getenv("DEVICE_SCAN_INTERVAL", "30"))  # seconds
        self.max_devices = int(os.getenv("MAX_DEVICES", "10"))
        self.enable_arp_monitoring = os.getenv("ENABLE_ARP_MONITORING", "true").lower() == "true"
        
        # Device tracking
        self.known_devices = {}
        self.device_history = {}
    
    async def start_monitoring(self):
        """Start device monitoring"""
        try:
            if self.monitoring:
                logger.info("Device monitoring is already running")
                return
            
            self.monitoring = True
            logger.info("🚀 Starting device monitoring...")
            
            # Start monitoring task
            self.monitor_task = asyncio.create_task(self._monitor_loop())
            
            logger.info("✅ Device monitoring started successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to start device monitoring: {e}")
            self.monitoring = False
    
    async def stop_monitoring(self):
        """Stop device monitoring"""
        try:
            if not self.monitoring:
                return
            
            logger.info("🛑 Stopping device monitoring...")
            
            self.monitoring = False
            
            if self.monitor_task:
                self.monitor_task.cancel()
                try:
                    await self.monitor_task
                except asyncio.CancelledError:
                    pass
            
            logger.info("✅ Device monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping device monitoring: {e}")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        try:
            while self.monitoring:
                # Scan for devices
                await self._scan_devices()
                
                # Update device status
                await self._update_device_status()
                
                # Clean up old devices
                await self._cleanup_old_devices()
                
                # Wait for next scan
                await asyncio.sleep(self.scan_interval)
                
        except asyncio.CancelledError:
            logger.info("Device monitoring cancelled")
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            self.monitoring = False
    
    async def _scan_devices(self):
        """Scan for connected devices"""
        try:
            # Get devices from ARP table
            arp_devices = self._get_arp_devices()
            
            # Get devices from WiFi interface
            wifi_devices = self._get_wifi_devices()
            
            # Merge device information
            current_devices = self._merge_device_info(arp_devices, wifi_devices)
            
            # Update database
            await self._update_device_database(current_devices)
            
            # Update known devices
            with self._lock:
                self.known_devices = current_devices
            
            logger.debug(f"Scanned {len(current_devices)} devices")
            
        except Exception as e:
            logger.error(f"Error scanning devices: {e}")
    
    def _get_arp_devices(self) -> Dict[str, Dict[str, Any]]:
        """Get devices from ARP table"""
        try:
            devices = {}
            
            # Run arp command
            result = subprocess.run(
                ["arp", "-n"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse ARP output
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('Address'):
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[2]
                            
                            # Skip broadcast and multicast
                            if ip not in ['0.0.0.0', '255.255.255.255'] and mac != '<incomplete>':
                                devices[ip] = {
                                    'ip_address': ip,
                                    'mac_address': mac,
                                    'hostname': self._get_hostname(ip),
                                    'last_seen': datetime.now(),
                                    'source': 'arp'
                                }
            
            return devices
            
        except Exception as e:
            logger.error(f"Error getting ARP devices: {e}")
            return {}
    
    def _get_wifi_devices(self) -> Dict[str, Dict[str, Any]]:
        """Get devices from WiFi interface"""
        try:
            devices = {}
            
            # Try to get devices from hostapd
            if os.path.exists('/var/run/hostapd'):
                result = subprocess.run(
                    ["hostapd_cli", "-i", "wlan0", "all_sta"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    current_mac = None
                    for line in result.stdout.split('\n'):
                        if line.startswith('sta'):
                            current_mac = line.split('=')[1]
                        elif line.startswith('ipaddr') and current_mac:
                            ip = line.split('=')[1]
                            if ip and ip != '0.0.0.0':
                                devices[ip] = {
                                    'ip_address': ip,
                                    'mac_address': current_mac,
                                    'hostname': self._get_hostname(ip),
                                    'last_seen': datetime.now(),
                                    'source': 'wifi'
                                }
            
            return devices
            
        except Exception as e:
            logger.error(f"Error getting WiFi devices: {e}")
            return {}
    
    def _get_hostname(self, ip_address: str) -> Optional[str]:
        """Get hostname for IP address"""
        try:
            # Try reverse DNS lookup
            result = subprocess.run(
                ["nslookup", ip_address],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Parse nslookup output
                for line in result.stdout.split('\n'):
                    if 'name = ' in line:
                        hostname = line.split('name = ')[1].strip().rstrip('.')
                        if hostname and hostname != ip_address:
                            return hostname
            
            return None
            
        except Exception as e:
            logger.debug(f"Error getting hostname for {ip_address}: {e}")
            return None
    
    def _merge_device_info(self, arp_devices: Dict, wifi_devices: Dict) -> Dict[str, Dict[str, Any]]:
        """Merge device information from different sources"""
        try:
            merged = {}
            
            # Start with ARP devices
            for ip, device in arp_devices.items():
                merged[ip] = device.copy()
            
            # Merge WiFi information
            for ip, device in wifi_devices.items():
                if ip in merged:
                    # Update existing device
                    merged[ip].update(device)
                    merged[ip]['source'] = 'both'
                else:
                    # Add new device
                    merged[ip] = device.copy()
            
            return merged
            
        except Exception as e:
            logger.error(f"Error merging device info: {e}")
            return {}
    
    async def _update_device_database(self, current_devices: Dict[str, Dict[str, Any]]):
        """Update device database"""
        try:
            for ip, device_info in current_devices.items():
                # Check if device exists in database
                existing_device = self._get_device_from_db(ip)
                
                if existing_device:
                    # Update existing device
                    self._update_device_in_db(ip, device_info)
                else:
                    # Add new device
                    self._add_device_to_db(device_info)
                    
                    # Log new device connection
                    self.db.add_log(
                        "info",
                        f"New device connected: {ip} ({device_info.get('hostname', 'Unknown')})",
                        ip,
                        user_agent="Device Monitor"
                    )
                    
                    logger.info(f"🚀 New device connected: {ip} ({device_info.get('hostname', 'Unknown')})")
            
            # Check for disconnected devices
            await self._check_disconnected_devices(current_devices)
            
        except Exception as e:
            logger.error(f"Error updating device database: {e}")
    
    def _get_device_from_db(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get device from database"""
        try:
            devices = self.db.get_devices()
            for device in devices:
                if device['ip_address'] == ip_address:
                    return device
            return None
        except Exception as e:
            logger.error(f"Error getting device from DB: {e}")
            return None
    
    def _update_device_in_db(self, ip_address: str, device_info: Dict[str, Any]):
        """Update device in database"""
        try:
            # Update last seen time
            self.db.update_device_status(ip_address, "active")
            
            # Update device history
            with self._lock:
                if ip_address not in self.device_history:
                    self.device_history[ip_address] = []
                
                self.device_history[ip_address].append({
                    'timestamp': datetime.now(),
                    'status': 'active',
                    'source': device_info.get('source', 'unknown')
                })
                
                # Keep only last 100 entries
                if len(self.device_history[ip_address]) > 100:
                    self.device_history[ip_address] = self.device_history[ip_address][-100:]
                    
        except Exception as e:
            logger.error(f"Error updating device in DB: {e}")
    
    def _add_device_to_db(self, device_info: Dict[str, Any]):
        """Add new device to database"""
        try:
            self.db.add_device(
                device_info['ip_address'],
                device_info['mac_address'],
                device_info.get('hostname')
            )
        except Exception as e:
            logger.error(f"Error adding device to DB: {e}")
    
    async def _check_disconnected_devices(self, current_devices: Dict[str, Dict[str, Any]]):
        """Check for disconnected devices"""
        try:
            # Get all devices from database
            db_devices = self.db.get_devices()
            
            for db_device in db_devices:
                ip = db_device['ip_address']
                
                if ip not in current_devices:
                    # Device not found in current scan
                    if db_device['status'] == 'active':
                        # Mark as disconnected
                        self.db.update_device_status(ip, "disconnected")
                        
                        # Log disconnection
                        self.db.add_log(
                            "warning",
                            f"Device disconnected: {ip}",
                            ip,
                            user_agent="Device Monitor"
                        )
                        
                        logger.info(f"📱 Device disconnected: {ip}")
                        
                        # Update device history
                        with self._lock:
                            if ip not in self.device_history:
                                self.device_history[ip] = []
                            
                            self.device_history[ip].append({
                                'timestamp': datetime.now(),
                                'status': 'disconnected',
                                'source': 'monitor'
                            })
                
        except Exception as e:
            logger.error(f"Error checking disconnected devices: {e}")
    
    async def _update_device_status(self):
        """Update device status and statistics"""
        try:
            # Update data usage statistics
            await self._update_data_usage()
            
            # Check for suspicious activity
            await self._check_suspicious_activity()
            
        except Exception as e:
            logger.error(f"Error updating device status: {e}")
    
    async def _update_data_usage(self):
        """Update device data usage statistics"""
        try:
            # This is a simplified implementation
            # In a real system, you might use iptables counters or other methods
            
            for ip, device_info in self.known_devices.items():
                # Simulate data usage update
                # In practice, you'd get this from network statistics
                pass
                
        except Exception as e:
            logger.error(f"Error updating data usage: {e}")
    
    async def _check_suspicious_activity(self):
        """Check for suspicious device activity"""
        try:
            # Check for devices with unusual traffic patterns
            # This is a placeholder for security monitoring
            
            for ip, device_info in self.known_devices.items():
                # Example: Check for excessive connection attempts
                # In practice, you'd implement more sophisticated detection
                pass
                
        except Exception as e:
            logger.error(f"Error checking suspicious activity: {e}")
    
    async def _cleanup_old_devices(self):
        """Clean up old disconnected devices"""
        try:
            # Remove devices that have been disconnected for more than 24 hours
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            db_devices = self.db.get_devices()
            
            for device in db_devices:
                if device['status'] == 'disconnected':
                    # Check last seen time
                    if 'last_seen' in device and device['last_seen']:
                        if device['last_seen'] < cutoff_time:
                            # Remove old disconnected device
                            self.db.remove_device(device['ip_address'])
                            
                            # Clean up history
                            with self._lock:
                                if device['ip_address'] in self.device_history:
                                    del self.device_history[device['ip_address']]
                            
                            logger.info(f"🧹 Cleaned up old device: {device['ip_address']}")
                
        except Exception as e:
            logger.error(f"Error cleaning up old devices: {e}")
    
    def get_device_history(self, ip_address: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get device connection history"""
        try:
            with self._lock:
                if ip_address in self.device_history:
                    history = self.device_history[ip_address][-limit:]
                    return [
                        {
                            'timestamp': entry['timestamp'].isoformat(),
                            'status': entry['status'],
                            'source': entry['source']
                        }
                        for entry in history
                    ]
                return []
                
        except Exception as e:
            logger.error(f"Error getting device history: {e}")
            return []
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        try:
            status = {
                'monitoring': self.monitoring,
                'scan_interval': self.scan_interval,
                'max_devices': self.max_devices,
                'known_devices': len(self.known_devices),
                'arp_monitoring': self.enable_arp_monitoring,
                'last_scan': getattr(self, '_last_scan_time', None)
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting monitoring status: {e}")
            return {'monitoring': False, 'error': str(e)}
    
    def force_scan(self):
        """Force an immediate device scan"""
        try:
            if self.monitoring:
                # Create a task for immediate scan
                asyncio.create_task(self._scan_devices())
                logger.info("Forced device scan initiated")
            else:
                logger.warning("Cannot force scan - monitoring not running")
                
        except Exception as e:
            logger.error(f"Error forcing device scan: {e}")
    
    def get_device_count(self) -> int:
        """Get current device count"""
        try:
            with self._lock:
                return len(self.known_devices)
        except Exception as e:
            logger.error(f"Error getting device count: {e}")
            return 0
