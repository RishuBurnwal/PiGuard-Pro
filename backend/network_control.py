#!/usr/bin/env python3
"""
🌐 Target-Centric Admin Dashboard - Network Control Module
Network traffic control optimized for Raspberry Pi Zero W
"""

import os
import logging
import subprocess
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
import json
import re

logger = logging.getLogger(__name__)

class NetworkControl:
    """Network traffic control for Pi Zero W hotspot"""
    
    def __init__(self):
        self.wifi_interface = os.getenv("WIFI_INTERFACE", "wlan0")
        self.bridge_interface = os.getenv("BRIDGE_INTERFACE", "br0")
        self.dhcp_range_start = os.getenv("DHCP_START", "192.168.50.10")
        self.dhcp_range_end = os.getenv("DHCP_END", "192.168.50.100")
        self.gateway_ip = os.getenv("GATEWAY_IP", "192.168.50.1")
        
        # Pi Zero W specific settings
        self.max_connections = int(os.getenv("MAX_CONNECTIONS", "10"))
        self.enable_qos = os.getenv("ENABLE_QOS", "true").lower() == "true"
        
        # Track active rules
        self.active_rules = {}
        self._lock = threading.Lock()
        
        # Initialize network
        self._init_network()
    
    def _init_network(self):
        """Initialize network configuration"""
        try:
            logger.info("🌐 Initializing network control for Pi Zero W...")
            
            # Check if running as root
            if os.geteuid() != 0:
                logger.warning("⚠️ Network control requires root privileges")
                return
            
            # Setup basic iptables
            self._setup_iptables()
            
            # Setup traffic shaping if enabled
            if self.enable_qos:
                self._setup_traffic_shaping()
            
            logger.info("✅ Network control initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize network control: {e}")
    
    def _setup_iptables(self):
        """Setup basic iptables rules"""
        try:
            # Flush existing rules
            self._run_command("iptables -F")
            self._run_command("iptables -t nat -F")
            
            # Allow established connections
            self._run_command("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
            self._run_command("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
            
            # Allow loopback
            self._run_command("iptables -A INPUT -i lo -j ACCEPT")
            
            # Allow SSH (if needed)
            self._run_command("iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
            
            # Allow HTTP/HTTPS for admin dashboard
            self._run_command("iptables -A INPUT -p tcp --dport 8000 -j ACCEPT")
            
            # Setup NAT for internet access
            self._run_command(f"iptables -t nat -A POSTROUTING -o {self.bridge_interface} -j MASQUERADE")
            
            # Allow forwarding from WiFi to bridge
            self._run_command(f"iptables -A FORWARD -i {self.wifi_interface} -o {self.bridge_interface} -j ACCEPT")
            self._run_command(f"iptables -A FORWARD -i {self.bridge_interface} -o {self.wifi_interface} -j ACCEPT")
            
            # Set default policies
            self._run_command("iptables -P INPUT DROP")
            self._run_command("iptables -P FORWARD DROP")
            self._run_command("iptables -P OUTPUT ACCEPT")
            
            logger.info("✅ iptables rules configured")
            
        except Exception as e:
            logger.error(f"Error setting up iptables: {e}")
    
    def _setup_traffic_shaping(self):
        """Setup traffic shaping with tc (traffic control)"""
        try:
            # Remove existing qdisc
            self._run_command(f"tc qdisc del dev {self.wifi_interface} root", ignore_errors=True)
            
            # Add root qdisc
            self._run_command(f"tc qdisc add dev {self.wifi_interface} root handle 1: htb default 30")
            
            # Add main class for total bandwidth
            self._run_command(f"tc class add dev {self.wifi_interface} parent 1: classid 1:1 htb rate 10Mbit")
            
            # Add default class for normal traffic
            self._run_command(f"tc class add dev {self.wifi_interface} parent 1:1 classid 1:30 htb rate 5Mbit")
            
            logger.info("✅ Traffic shaping configured")
            
        except Exception as e:
            logger.error(f"Error setting up traffic shaping: {e}")
    
    def _run_command(self, command: str, ignore_errors: bool = False) -> Tuple[bool, str]:
        """Run shell command with error handling"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30  # Timeout for Pi Zero W
            )
            
            if result.returncode == 0 or ignore_errors:
                return True, result.stdout.strip()
            else:
                logger.error(f"Command failed: {command}")
                logger.error(f"Error: {result.stderr}")
                return False, result.stderr.strip()
                
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {command}")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"Error running command '{command}': {e}")
            return False, str(e)
    
    # ============================================================================
    # DEVICE CONTROL METHODS
    # ============================================================================
    
    def block_device(self, ip_address: str) -> bool:
        """Block device from network access"""
        try:
            with self._lock:
                # Add iptables rule to block device
                success, _ = self._run_command(
                    f"iptables -A FORWARD -s {ip_address} -j DROP"
                )
                
                if success:
                    # Track blocked device
                    self.active_rules[f"block_{ip_address}"] = {
                        'type': 'block',
                        'ip': ip_address,
                        'created': time.time()
                    }
                    
                    logger.info(f"Device {ip_address} blocked successfully")
                    return True
                else:
                    logger.error(f"Failed to block device {ip_address}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error blocking device {ip_address}: {e}")
            return False
    
    def unblock_device(self, ip_address: str) -> bool:
        """Unblock device"""
        try:
            with self._lock:
                # Remove iptables rule
                success, _ = self._run_command(
                    f"iptables -D FORWARD -s {ip_address} -j DROP"
                )
                
                if success:
                    # Remove from tracking
                    rule_key = f"block_{ip_address}"
                    if rule_key in self.active_rules:
                        del self.active_rules[rule_key]
                    
                    logger.info(f"Device {ip_address} unblocked successfully")
                    return True
                else:
                    logger.error(f"Failed to unblock device {ip_address}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error unblocking device {ip_address}: {e}")
            return False
    
    def throttle_device(self, ip_address: str, bandwidth_limit: str) -> bool:
        """Throttle device bandwidth"""
        try:
            with self._lock:
                # Parse bandwidth limit
                rate = self._parse_bandwidth(bandwidth_limit)
                if not rate:
                    logger.error(f"Invalid bandwidth limit: {bandwidth_limit}")
                    return False
                
                # Create unique class ID
                class_id = self._get_next_class_id()
                
                # Add traffic class for device
                success, _ = self._run_command(
                    f"tc class add dev {self.wifi_interface} parent 1:1 classid 1:{class_id} htb rate {rate}"
                )
                
                if success:
                    # Add filter to route device traffic to this class
                    success, _ = self._run_command(
                        f"tc filter add dev {self.wifi_interface} parent 1: protocol ip u32 match ip src {ip_address}/32 flowid 1:{class_id}"
                    )
                    
                    if success:
                        # Track throttled device
                        self.active_rules[f"throttle_{ip_address}"] = {
                            'type': 'throttle',
                            'ip': ip_address,
                            'class_id': class_id,
                            'rate': rate,
                            'created': time.time()
                        }
                        
                        logger.info(f"Device {ip_address} throttled to {bandwidth_limit}")
                        return True
                
                logger.error(f"Failed to throttle device {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"Error throttling device {ip_address}: {e}")
            return False
    
    def remove_throttle(self, ip_address: str) -> bool:
        """Remove device throttling"""
        try:
            with self._lock:
                rule_key = f"throttle_{ip_address}"
                if rule_key not in self.active_rules:
                    return True  # Already not throttled
                
                rule = self.active_rules[rule_key]
                class_id = rule['class_id']
                
                # Remove filter
                self._run_command(
                    f"tc filter del dev {self.wifi_interface} parent 1: protocol ip u32 match ip src {ip_address}/32",
                    ignore_errors=True
                )
                
                # Remove class
                self._run_command(
                    f"tc class del dev {self.wifi_interface} parent 1:1 classid 1:{class_id}",
                    ignore_errors=True
                )
                
                # Remove from tracking
                del self.active_rules[rule_key]
                
                logger.info(f"Throttling removed for device {ip_address}")
                return True
                
        except Exception as e:
            logger.error(f"Error removing throttle for device {ip_address}: {e}")
            return False
    
    def kick_device(self, ip_address: str) -> bool:
        """Kick device from WiFi network"""
        try:
            # Get device MAC address
            mac_address = self._get_device_mac(ip_address)
            if not mac_address:
                logger.error(f"Could not find MAC address for {ip_address}")
                return False
            
            # Use hostapd_cli to deauthenticate device
            success, _ = self._run_command(
                f"hostapd_cli -i {self.wifi_interface} deauthenticate {mac_address}"
            )
            
            if success:
                logger.info(f"Device {ip_address} ({mac_address}) kicked from network")
                return True
            else:
                logger.error(f"Failed to kick device {ip_address}")
                return False
                
        except Exception as e:
            logger.error(f"Error kicking device {ip_address}: {e}")
            return False
    
    # ============================================================================
    # DNS AND REDIRECTION
    # ============================================================================
    
    def add_dns_rule(self, domain: str, action: str, target_ip: str = None) -> bool:
        """Add DNS rule for domain"""
        try:
            if action == "block":
                # Add to dnsmasq blacklist
                self._add_to_dnsmasq_blacklist(domain)
            elif action == "redirect" and target_ip:
                # Add DNS redirection
                self._add_dns_redirection(domain, target_ip)
            
            logger.info(f"DNS rule added for {domain}: {action}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding DNS rule for {domain}: {e}")
            return False
    
    def _add_to_dnsmasq_blacklist(self, domain: str):
        """Add domain to dnsmasq blacklist"""
        try:
            # Add to dnsmasq configuration
            blacklist_file = "/etc/dnsmasq.d/blacklist.conf"
            with open(blacklist_file, "a") as f:
                f.write(f"address=/{domain}/0.0.0.0\n")
            
            # Reload dnsmasq
            self._run_command("systemctl reload dnsmasq")
            
        except Exception as e:
            logger.error(f"Error adding to dnsmasq blacklist: {e}")
    
    def _add_dns_redirection(self, domain: str, target_ip: str):
        """Add DNS redirection rule"""
        try:
            # Add to dnsmasq configuration
            redirect_file = "/etc/dnsmasq.d/redirect.conf"
            with open(redirect_file, "a") as f:
                f.write(f"address=/{domain}/{target_ip}\n")
            
            # Reload dnsmasq
            self._run_command("systemctl reload dnsmasq")
            
        except Exception as e:
            logger.error(f"Error adding DNS redirection: {e}")
    
    # ============================================================================
    # UTILITY METHODS
    # ============================================================================
    
    def _parse_bandwidth(self, bandwidth_str: str) -> Optional[str]:
        """Parse bandwidth string to tc format"""
        try:
            # Support formats: 1Mbps, 500Kbps, 1Gbps
            match = re.match(r'(\d+)([KMGT])?bps', bandwidth_str, re.IGNORECASE)
            if match:
                value = int(match.group(1))
                unit = match.group(2).upper() if match.group(2) else ""
                
                if unit == "K":
                    return f"{value}kbit"
                elif unit == "M":
                    return f"{value}mbit"
                elif unit == "G":
                    return f"{value}gbit"
                else:
                    return f"{value}bit"
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing bandwidth: {e}")
            return None
    
    def _get_next_class_id(self) -> int:
        """Get next available traffic class ID"""
        used_ids = set()
        for rule in self.active_rules.values():
            if rule['type'] == 'throttle':
                used_ids.add(rule['class_id'])
        
        # Start from 10 to avoid conflicts
        for i in range(10, 100):
            if i not in used_ids:
                return i
        
        return 99  # Fallback
    
    def _get_device_mac(self, ip_address: str) -> Optional[str]:
        """Get device MAC address from ARP table"""
        try:
            success, output = self._run_command("arp -n")
            if success:
                # Parse ARP output
                for line in output.split('\n'):
                    if ip_address in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting MAC address: {e}")
            return None
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status"""
        try:
            status = {
                'wifi_interface': self.wifi_interface,
                'bridge_interface': self.bridge_interface,
                'gateway_ip': self.gateway_ip,
                'dhcp_range': f"{self.dhcp_range_start}-{self.dhcp_range_end}",
                'active_rules': len(self.active_rules),
                'qos_enabled': self.enable_qos,
                'max_connections': self.max_connections
            }
            
            # Get interface statistics
            success, output = self._run_command(f"cat /sys/class/net/{self.wifi_interface}/statistics/rx_bytes")
            if success:
                status['rx_bytes'] = int(output) if output.isdigit() else 0
            
            success, output = self._run_command(f"cat /sys/class/net/{self.wifi_interface}/statistics/tx_bytes")
            if success:
                status['tx_bytes'] = int(output) if output.isdigit() else 0
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting network status: {e}")
            return {}
    
    def cleanup_rules(self) -> int:
        """Clean up old rules (Pi Zero W maintenance)"""
        try:
            current_time = time.time()
            cleaned_count = 0
            
            with self._lock:
                rules_to_remove = []
                
                for rule_key, rule in self.active_rules.items():
                    # Remove rules older than 24 hours
                    if current_time - rule['created'] > 86400:
                        rules_to_remove.append(rule_key)
                
                for rule_key in rules_to_remove:
                    rule = self.active_rules[rule_key]
                    
                    if rule['type'] == 'block':
                        self.unblock_device(rule['ip'])
                    elif rule['type'] == 'throttle':
                        self.remove_throttle(rule['ip'])
                    
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} old network rules")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Error cleaning up rules: {e}")
            return 0
    
    def restart_services(self) -> bool:
        """Restart network services"""
        try:
            logger.info("🔄 Restarting network services...")
            
            # Restart dnsmasq
            self._run_command("systemctl restart dnsmasq")
            
            # Restart hostapd
            self._run_command("systemctl restart hostapd")
            
            # Reapply iptables rules
            self._setup_iptables()
            
            logger.info("✅ Network services restarted")
            return True
            
        except Exception as e:
            logger.error(f"Error restarting network services: {e}")
            return False
