#!/usr/bin/env python3
"""
🔍 Target-Centric Admin Dashboard - MitmProxy Controller
Content modification and traffic interception for Pi Zero W
"""

import os
import logging
import subprocess
import time
import threading
import json
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class MitmProxyController:
    """MitmProxy controller for content modification and traffic interception"""
    
    def __init__(self):
        self.port = int(os.getenv("MITMPROXY_PORT", "8080"))
        self.interface = os.getenv("MITMPROXY_INTERFACE", "0.0.0.0")
        self.script_path = "scripts/mitmproxy_rules.py"
        self.process = None
        self.is_running_flag = False
        self._lock = threading.Lock()
        
        # Pi Zero W specific settings
        self.max_connections = int(os.getenv("MAX_MITM_CONNECTIONS", "20"))
        self.enable_ssl = os.getenv("ENABLE_SSL_INTERCEPTION", "false").lower() == "true"
        
        # Ensure script directory exists
        self._ensure_script_directory()
    
    def _ensure_script_directory(self):
        """Ensure the scripts directory exists"""
        try:
            scripts_dir = Path("scripts")
            scripts_dir.mkdir(exist_ok=True)
            
            # Create the mitmproxy script if it doesn't exist
            script_file = scripts_dir / "mitmproxy_rules.py"
            if not script_file.exists():
                self._create_default_script(script_file)
                
        except Exception as e:
            logger.error(f"Error ensuring script directory: {e}")
    
    def _create_default_script(self, script_path: Path):
        """Create default mitmproxy script"""
        try:
                        script_content = '''#!/usr/bin/env python3
"""
🎯 MitmProxy Rules Script for Target-Centric Admin Dashboard
Content modification and filtering rules
"""

from mitmproxy import http
import sqlite3
import json
import logging
import time
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RulesEngine:
    """Rules engine for content modification"""
    
    def __init__(self):
        self.db_path = "hotspot_control.db"
        self.rules_cache = []
        self.last_update = 0
        self.cache_ttl = 60  # Cache rules for 60 seconds
        
    def get_rules(self):
        """Get active rules from database"""
        try:
            current_time = time.time()
            
            # Return cached rules if still valid
            if current_time - self.last_update < self.cache_ttl and self.rules_cache:
                return self.rules_cache
            
            # Fetch fresh rules from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT pattern, action, applied_to, status, tags
                FROM rules 
                WHERE status = 'on'
                ORDER BY priority ASC
            """)
            
            rules = []
            for row in cursor.fetchall():
                pattern, action, applied_to, status, tags = row
                
                # Parse tags
                try:
                    tags_list = json.loads(tags) if tags else []
                except:
                    tags_list = []
                
                rules.append({
                    'pattern': pattern,
                    'action': action,
                    'applied_to': applied_to,
                    'tags': tags_list
                })
            
            conn.close()
            
            # Update cache
            self.rules_cache = rules
            self.last_update = current_time
            
            return rules
            
        except Exception as e:
            logger.error(f"Error getting rules: {e}")
            return []
    
    def should_apply_rule(self, rule, client_ip: str) -> bool:
        """Check if rule should be applied to this client"""
        if rule['applied_to'] == 'all':
            return True
        return rule['applied_to'] == client_ip
    
    def match_pattern(self, pattern: str, url: str) -> bool:
        """Check if URL matches pattern"""
        try:
            if pattern.startswith('*.'):
                # Wildcard domain
                domain = pattern[2:]
                return domain in url
            elif pattern.startswith('*'):
                # Wildcard path
                path = pattern[1:]
                return path in url
            else:
                # Exact match
                return pattern in url
        except:
            return False

# Global rules engine instance
rules_engine = RulesEngine()

def request(flow: http.HTTPFlow):
    """Handle HTTP requests with logging and rule processing"""
    try:
        # Log the request first
        log_request(flow)
        
        client_ip = flow.client_conn.ip_address[0]
        url = flow.request.pretty_url
        
        # Get active rules
        rules = rules_engine.get_rules()
        
        for rule in rules:
            # Check if rule applies to this client
            if not rules_engine.should_apply_rule(rule, client_ip):
                continue
            
            # Check if URL matches pattern
            if not rules_engine.match_pattern(rule['pattern'], url):
                continue
            
            # Apply rule action
            apply_rule_action(flow, rule, url)
            break
            
    except Exception as e:
        logger.error(f"Error in request handler: {e}")

def apply_rule_action(flow: http.HTTPFlow, rule: dict, url: str):
    """Apply rule action to the request"""
    try:
        action = rule['action']
        
        if action == 'block':
            # Block the request
            flow.response = http.Response.make(
                403, 
                b"Access Denied - Content blocked by admin",
                {"Content-Type": "text/plain"}
            )
            logger.info(f"Blocked {url} for client {flow.client_conn.ip_address[0]}")
            
        elif action == 'redirect':
            # Redirect to different URL
            if '→' in rule['pattern']:
                redirect_url = rule['pattern'].split('→')[1].strip()
                flow.response = http.Response.make(
                    302,
                    b"",
                    {"Location": redirect_url}
                )
                logger.info(f"Redirected {url} to {redirect_url}")
                
        elif action == 'throttle':
            # Add delay for throttling
            time.sleep(0.1)  # 100ms delay
            logger.info(f"Throttled {url}")
            
    except Exception as e:
        logger.error(f"Error applying rule action: {e}")

def response(flow: http.HTTPFlow):
    """Handle HTTP responses"""
    try:
        client_ip = flow.client_conn.ip_address[0]
        url = flow.request.pretty_url
        
        # Get active rules
        rules = rules_engine.get_rules()
        
        for rule in rules:
            # Check if rule applies to this client
            if not rules_engine.should_apply_rule(rule, client_ip):
                continue
            
            # Check if URL matches pattern
            if not rules_engine.match_pattern(rule['pattern'], url):
                continue
            
            # Apply response modifications
            if rule['action'] == 'modify':
                modify_response(flow, rule)
                break
                
    except Exception as e:
        logger.error(f"Error in response handler: {e}")

def modify_response(flow: http.HTTPFlow, rule: dict):
    """Modify response content"""
    try:
        if 'image' in rule.get('tags', []):
            # Replace images with placeholder
            placeholder_image = b"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
            flow.response.content = placeholder_image
            flow.response.headers["Content-Type"] = "image/png"
            logger.info(f"Replaced image in {flow.request.pretty_url}")
            
        elif 'text' in rule.get('tags', []):
            # Replace text content
            if flow.response.text:
                # Simple text replacement (YouTube -> StudyHub)
                modified_text = flow.response.text.replace("YouTube", "StudyHub")
                flow.response.text = modified_text
                logger.info(f"Modified text in {flow.request.pretty_url}")
                
    except Exception as e:
        logger.error(f"Error modifying response: {e}")

def log_request(flow: http.HTTPFlow):
    """Log request for monitoring"""
    try:
        client_ip = flow.client_conn.ip_address[0]
        url = flow.request.pretty_url
        user_agent = flow.request.headers.get("User-Agent", "")
        
        # Log to database
        log_to_database(client_ip, url, user_agent, 0)  # Response not available yet
        
    except Exception as e:
        logger.error(f"Error logging request: {e}")

def log_to_database(ip: str, url: str, user_agent: str, data_size: int):
    """Log request to database"""
    try:
        conn = sqlite3.connect("hotspot_control.db")
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO logs (level, message, ip_address, url, user_agent, data_size)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "info",
            f"HTTP request to {url}",
            ip,
            url,
            user_agent,
            data_size
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error logging to database: {e}")
'''
            
            script_path.write_text(script_content)
            logger.info(f"Created default mitmproxy script: {script_path}")
            
        except Exception as e:
            logger.error(f"Error creating default script: {e}")
    
    def start(self) -> bool:
        """Start mitmproxy service"""
        try:
            with self._lock:
                if self.is_running_flag:
                    logger.info("MitmProxy is already running")
                    return True
                
                # Build command
                cmd = [
                    "mitmdump",
                    "--listen-port", str(self.port),
                    "--listen-host", self.interface,
                    "--scripts", self.script_path,
                    "--set", f"confdir=~/.mitmproxy",
                    "--set", f"max_connections={self.max_connections}"
                ]
                
                # Add SSL options if enabled
                if self.enable_ssl:
                    cmd.extend(["--ssl-insecure"])
                
                # Start process
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Wait a moment to check if it started successfully
                time.sleep(2)
                
                if self.process.poll() is None:
                    self.is_running_flag = True
                    logger.info(f"✅ MitmProxy started on port {self.port}")
                    return True
                else:
                    # Process failed to start
                    stdout, stderr = self.process.communicate()
                    logger.error(f"MitmProxy failed to start: {stderr}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error starting MitmProxy: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop mitmproxy service"""
        try:
            with self._lock:
                if not self.is_running_flag:
                    return True
                
                if self.process:
                    # Send SIGTERM
                    self.process.terminate()
                    
                    # Wait for graceful shutdown
                    try:
                        self.process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        # Force kill if not responding
                        self.process.kill()
                        self.process.wait()
                    
                    self.process = None
                
                self.is_running_flag = False
                logger.info("✅ MitmProxy stopped")
                return True
                
        except Exception as e:
            logger.error(f"Error stopping MitmProxy: {e}")
            return False
    
    def restart(self) -> bool:
        """Restart mitmproxy service"""
        try:
            logger.info("🔄 Restarting MitmProxy...")
            
            if self.stop():
                time.sleep(2)  # Wait a bit before restarting
                return self.start()
            
            return False
            
        except Exception as e:
            logger.error(f"Error restarting MitmProxy: {e}")
            return False
    
    def is_running(self) -> bool:
        """Check if mitmproxy is running"""
        with self._lock:
            if not self.is_running_flag:
                return False
            
            if self.process and self.process.poll() is None:
                return True
            
            # Process has died
            self.is_running_flag = False
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get mitmproxy status"""
        try:
            status = {
                'running': self.is_running(),
                'port': self.port,
                'interface': self.interface,
                'max_connections': self.max_connections,
                'ssl_enabled': self.enable_ssl,
                'script_path': str(self.script_path)
            }
            
            if self.process:
                status['pid'] = self.process.pid
                status['returncode'] = self.process.returncode
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {'running': False, 'error': str(e)}
    
    def reload_rules(self) -> bool:
        """Reload rules by restarting the service"""
        try:
            if self.is_running():
                logger.info("Reloading MitmProxy rules...")
                return self.restart()
            else:
                return self.start()
                
        except Exception as e:
            logger.error(f"Error reloading rules: {e}")
            return False
    
    def get_logs(self, lines: int = 100) -> List[str]:
        """Get recent mitmproxy logs"""
        try:
            if not self.process:
                return []
            
            # This is a simplified log retrieval
            # In a real implementation, you might want to capture stdout/stderr
            return [f"MitmProxy running on port {self.port}"]
            
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return []
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            self.stop()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Destructor"""
        self.cleanup()
