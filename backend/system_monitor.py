#!/usr/bin/env python3
"""
📊 Target-Centric Admin Dashboard - System Monitor
Real-time system monitoring for Raspberry Pi Zero W
"""

import os
import logging
import time
import subprocess
from typing import Dict, Any, Optional
import psutil
import threading
import asyncio

logger = logging.getLogger(__name__)

class SystemMonitor:
    """System monitoring for Pi Zero W"""
    
    def __init__(self):
        self.is_pi_zero_w = self._detect_pi_zero_w()
        self.monitoring = False
        self.monitor_task = None
        self._lock = threading.Lock()
        
        # Pi Zero W specific settings
        self.monitor_interval = int(os.getenv("SYSTEM_MONITOR_INTERVAL", "30"))  # seconds
        self.enable_temp_monitoring = os.getenv("ENABLE_TEMP_MONITORING", "true").lower() == "true"
        self.enable_gpio_monitoring = os.getenv("ENABLE_GPIO_MONITORING", "false").lower() == "true"
        
        # Cache for system metrics
        self.metrics_cache = {}
        self.cache_ttl = 10  # Cache for 10 seconds
        self.last_cache_update = 0
    
    def _detect_pi_zero_w(self) -> bool:
        """Detect if running on Raspberry Pi Zero W"""
        try:
            # Check for Pi Zero W specific identifiers
            if os.path.exists("/proc/device-tree/model"):
                with open("/proc/device-tree/model", "r") as f:
                    model = f.read().strip()
                    return "Raspberry Pi Zero W" in model
            
            # Fallback: check CPU info
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r") as f:
                    cpu_info = f.read()
                    return "BCM2835" in cpu_info or "ARM11" in cpu_info
            
            return False
            
        except Exception as e:
            logger.warning(f"Could not detect Pi Zero W: {e}")
            return False
    
    async def start_monitoring(self):
        """Start system monitoring"""
        try:
            if self.monitoring:
                logger.info("System monitoring is already running")
                return
            
            self.monitoring = True
            logger.info("📊 Starting system monitor...")
            
            # Start monitoring task
            self.monitor_task = asyncio.create_task(self._monitor_loop())
            
            logger.info("✅ System monitor started successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to start system monitor: {e}")
            self.monitoring = False
    
    async def stop_monitoring(self):
        """Stop system monitoring"""
        try:
            if not self.monitoring:
                return
            
            logger.info("🛑 Stopping system monitor...")
            
            self.monitoring = False
            
            if self.monitor_task:
                self.monitor_task.cancel()
                try:
                    await self.monitor_task
                except asyncio.CancelledError:
                    pass
            
            logger.info("✅ System monitor stopped")
            
        except Exception as e:
            logger.error(f"Error stopping system monitor: {e}")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        try:
            while self.monitoring:
                await self._update_metrics()
                await asyncio.sleep(self.monitor_interval)
                
        except asyncio.CancelledError:
            logger.info("System monitoring cancelled")
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            self.monitoring = False
    
    async def _update_metrics(self):
        """Update system metrics"""
        try:
            with self._lock:
                self.metrics_cache = {
                    'uptime': self._get_uptime(),
                    'cpu_usage': self._get_cpu_usage(),
                    'memory_usage': self._get_memory_usage(),
                    'temperature': self._get_temperature(),
                    'disk_usage': self._get_disk_usage(),
                    'network_stats': self._get_network_stats(),
                    'load_average': self._get_load_average(),
                    'timestamp': time.time()
                }
                self.last_cache_update = time.time()
                
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")
    
    def _get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            return time.time() - psutil.boot_time()
        except Exception as e:
            logger.error(f"Error getting uptime: {e}")
            return 0.0
    
    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        try:
            return psutil.cpu_percent(interval=1)
        except Exception as e:
            logger.error(f"Error getting CPU usage: {e}")
            return 0.0
    
    def _get_memory_usage(self) -> float:
        """Get memory usage percentage"""
        try:
            memory = psutil.virtual_memory()
            return memory.percent
        except Exception as e:
            logger.error(f"Error getting memory usage: {e}")
            return 0.0
    
    def _get_temperature(self) -> float:
        """Get CPU temperature in Celsius"""
        if not self.enable_temp_monitoring:
            return 0.0
        
        try:
            if self.is_pi_zero_w:
                # Pi Zero W temperature reading
                if os.path.exists("/sys/class/thermal/thermal_zone0/temp"):
                    with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
                        temp_millicelsius = int(f.read().strip())
                        return temp_millicelsius / 1000.0
                
                # Alternative method using vcgencmd
                try:
                    result = subprocess.run(
                        ["vcgencmd", "measure_temp"], 
                        capture_output=True, 
                        text=True, 
                        timeout=5
                    )
                    if result.returncode == 0:
                        temp_str = result.stdout.strip()
                        temp_celsius = float(temp_str.replace("temp=", "").replace("'C", ""))
                        return temp_celsius
                except:
                    pass
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Error getting temperature: {e}")
            return 0.0
    
    def _get_disk_usage(self) -> float:
        """Get disk usage percentage"""
        try:
            disk = psutil.disk_usage('/')
            return disk.percent
        except Exception as e:
            logger.error(f"Error getting disk usage: {e}")
            return 0.0
    
    def _get_network_stats(self) -> Dict[str, int]:
        """Get network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'rx_bytes': net_io.bytes_recv,
                'tx_bytes': net_io.bytes_sent,
                'rx_packets': net_io.packets_recv,
                'tx_packets': net_io.packets_sent
            }
        except Exception as e:
            logger.error(f"Error getting network stats: {e}")
            return {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0}
    
    def _get_load_average(self) -> list:
        """Get system load averages"""
        try:
            return list(psutil.getloadavg())
        except Exception as e:
            logger.error(f"Error getting load average: {e}")
            return [0.0, 0.0, 0.0]
    
    def get_system_status(self, wifi_devices_count: int = 0, active_rules_count: int = 0) -> Dict[str, Any]:
        """Get current system status"""
        try:
            current_time = time.time()
            
            # Return cached metrics if still valid
            if (current_time - self.last_cache_update < self.cache_ttl and 
                self.metrics_cache):
                metrics = self.metrics_cache.copy()
            else:
                # Force update if cache is stale
                self._update_metrics_sync()
                metrics = self.metrics_cache.copy()
            
            return {
                "system": "online",
                "uptime": metrics.get('uptime', 0.0),
                "cpu_usage": metrics.get('cpu_usage', 0.0),
                "memory_usage": metrics.get('memory_usage', 0.0),
                "temperature": metrics.get('temperature', 0.0),
                "disk_usage": metrics.get('disk_usage', 0.0),
                "wifi_connected_devices": wifi_devices_count,
                "active_rules": active_rules_count,
                "last_update": time.time()
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {
                "system": "error",
                "uptime": 0.0,
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "temperature": 0.0,
                "disk_usage": 0.0,
                "wifi_connected_devices": wifi_devices_count,
                "active_rules": active_rules_count,
                "last_update": time.time()
            }
    
    def get_system_performance(self) -> Dict[str, Any]:
        """Get detailed system performance metrics"""
        try:
            current_time = time.time()
            
            # Return cached metrics if still valid
            if (current_time - self.last_cache_update < self.cache_ttl and 
                self.metrics_cache):
                metrics = self.metrics_cache.copy()
            else:
                # Force update if cache is stale
                self._update_metrics_sync()
                metrics = self.metrics_cache.copy()
            
            # Get additional memory info
            memory = psutil.virtual_memory()
            
            return {
                "cpu_frequency": self._get_cpu_frequency(),
                "memory_available": memory.available // (1024 * 1024),  # Convert to MB
                "memory_total": memory.total // (1024 * 1024),  # Convert to MB
                "swap_usage": psutil.swap_memory().percent,
                "network_rx_bytes": metrics.get('network_stats', {}).get('rx_bytes', 0),
                "network_tx_bytes": metrics.get('network_stats', {}).get('tx_bytes', 0),
                "load_average": metrics.get('load_average', [0.0, 0.0, 0.0])
            }
            
        except Exception as e:
            logger.error(f"Error getting system performance: {e}")
            return {
                "cpu_frequency": 0.0,
                "memory_available": 0,
                "memory_total": 0,
                "swap_usage": 0.0,
                "network_rx_bytes": 0,
                "network_tx_bytes": 0,
                "load_average": [0.0, 0.0, 0.0]
            }
    
    def _get_cpu_frequency(self) -> float:
        """Get current CPU frequency in MHz"""
        try:
            if self.is_pi_zero_w:
                # Pi Zero W frequency reading
                if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"):
                    with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r") as f:
                        freq_khz = int(f.read().strip())
                        return freq_khz / 1000.0  # Convert to MHz
                
                # Alternative method using vcgencmd
                try:
                    result = subprocess.run(
                        ["vcgencmd", "measure_clock", "arm"], 
                        capture_output=True, 
                        text=True, 
                        timeout=5
                    )
                    if result.returncode == 0:
                        freq_str = result.stdout.strip()
                        freq_hz = int(freq_str.split("=")[1])
                        return freq_hz / 1000000.0  # Convert to MHz
                except:
                    pass
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Error getting CPU frequency: {e}")
            return 0.0
    
    def _update_metrics_sync(self):
        """Synchronous metrics update (for immediate use)"""
        try:
            self.metrics_cache = {
                'uptime': self._get_uptime(),
                'cpu_usage': self._get_cpu_usage(),
                'memory_usage': self._get_memory_usage(),
                'temperature': self._get_temperature(),
                'disk_usage': self._get_disk_usage(),
                'network_stats': self._get_network_stats(),
                'load_average': self._get_load_average(),
                'timestamp': time.time()
            }
            self.last_cache_update = time.time()
            
        except Exception as e:
            logger.error(f"Error in sync metrics update: {e}")
    
    def is_healthy(self) -> bool:
        """Check if system is healthy"""
        try:
            # Check critical metrics
            memory_usage = self._get_memory_usage()
            disk_usage = self._get_disk_usage()
            temperature = self._get_temperature()
            
            # Pi Zero W specific health checks
            if self.is_pi_zero_w:
                # Memory usage should be below 90%
                if memory_usage > 90:
                    logger.warning(f"High memory usage: {memory_usage}%")
                    return False
                
                # Disk usage should be below 95%
                if disk_usage > 95:
                    logger.warning(f"High disk usage: {disk_usage}%")
                    return False
                
                # Temperature should be below 80°C
                if temperature > 80:
                    logger.warning(f"High temperature: {temperature}°C")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking system health: {e}")
            return False
