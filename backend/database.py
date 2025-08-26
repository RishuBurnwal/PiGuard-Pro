#!/usr/bin/env python3
"""
🗄️ Target-Centric Admin Dashboard - Database Module
Single admin system optimized for Raspberry Pi Zero W
"""

import sqlite3
import logging
import os
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class Database:
    """Lightweight SQLite database optimized for Pi Zero W with single admin"""
    
    def __init__(self, db_path: str = "hotspot_control.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_connection()
    
    def _init_connection(self):
        """Initialize database connection with Pi Zero W optimizations"""
        try:
            # Create database directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else ".", exist_ok=True)
            
            # Connect to database
            self.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0  # Increased timeout for SD card I/O
            )
            
            # Pi Zero W specific optimizations
            self.conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
            self.conn.execute("PRAGMA synchronous=NORMAL")  # Balance between safety and performance
            self.conn.execute("PRAGMA cache_size=1000")  # 1MB cache (reasonable for 512MB RAM)
            self.conn.execute("PRAGMA temp_store=MEMORY")  # Store temp tables in memory
            self.conn.execute("PRAGMA mmap_size=268435456")  # 256MB memory mapping
            self.conn.execute("PRAGMA optimize")  # Optimize database
            
            logger.info("✅ Database initialized with Pi Zero W optimizations")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
            raise
    
    @contextmanager
    def get_cursor(self):
        """Context manager for database cursors with error handling"""
        cursor = None
        try:
            cursor = self.conn.cursor()
            yield cursor
            self.conn.commit()
        except Exception as e:
            if cursor:
                self.conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            with self.get_cursor() as cursor:
                # Create tables with optimized schemas
                
                # Single admin table (router-style)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS admins (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP
                    )
                """)
                
                # Devices table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS devices (
                        ip_address TEXT PRIMARY KEY,
                        mac_address TEXT NOT NULL,
                        hostname TEXT,
                        connected_since TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        bandwidth_limit TEXT,
                        data_usage INTEGER DEFAULT 0,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Rules table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        pattern TEXT NOT NULL,
                        action TEXT NOT NULL,
                        tags TEXT,  -- JSON array as text
                        applied_to TEXT DEFAULT 'all',
                        priority INTEGER DEFAULT 100,
                        status TEXT DEFAULT 'on',
                        description TEXT,
                        hit_count INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """
                )
                
                # Logs table (partitioned by date for Pi Zero W efficiency)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        level TEXT DEFAULT 'info',
                        message TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        url TEXT,
                        user_agent TEXT,
                        data_size INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Notifications table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        type TEXT NOT NULL,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        level TEXT DEFAULT 'info',
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        read BOOLEAN DEFAULT 0,
                        data TEXT  -- JSON data as text
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_status ON rules(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_date ON logs(ip_address, timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
                
                # Insert some default rules
                cursor.execute("SELECT COUNT(*) FROM rules")
                if cursor.fetchone()[0] == 0:
                    self._insert_default_rules(cursor)
                
                logger.info("✅ Database tables initialized successfully")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize database tables: {e}")
            raise
    
    def _insert_default_rules(self, cursor):
        """Insert default filtering rules"""
        default_rules = [
            ("Block Ads", "ads.", "block", "ads", "all", 10, "on", "Block common ad domains"),
            ("Block Social Media", "facebook.com", "block", "social", "all", 20, "on", "Block Facebook"),
            ("Study Mode", "youtube.com", "redirect", "study", "all", 30, "off", "Redirect YouTube to study resources"),
            ("Throttle Video", "*.mp4", "throttle", "video", "all", 40, "off", "Throttle video content"),
        ]
        
        for rule in default_rules:
            cursor.execute("""
                INSERT INTO rules (name, pattern, action, tags, applied_to, priority, status, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, rule)
    
    # ============================================================================
    # DEVICE MANAGEMENT
    # ============================================================================
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """Get all connected devices"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT ip_address, mac_address, hostname, connected_since, 
                           status, bandwidth_limit, data_usage, last_seen
                    FROM devices 
                    ORDER BY connected_since DESC
                """)
                
                columns = [desc[0] for desc in cursor.description]
                devices = []
                
                for row in cursor.fetchall():
                    device = dict(zip(columns, row))
                    # Convert timestamp strings to datetime objects
                    for time_field in ['connected_since', 'last_seen']:
                        if device[time_field]:
                            device[time_field] = datetime.fromisoformat(device[time_field])
                    devices.append(device)
                
                return devices
                
        except Exception as e:
            logger.error(f"Error getting devices: {e}")
            return []
    
    def add_device(self, ip_address: str, mac_address: str, hostname: str = None) -> bool:
        """Add new device"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    INSERT OR REPLACE INTO devices 
                    (ip_address, mac_address, hostname, connected_since, last_seen)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, (ip_address, mac_address, hostname))
                
                logger.info(f"Device {ip_address} added/updated")
                return True
                
        except Exception as e:
            logger.error(f"Error adding device {ip_address}: {e}")
            return False
    
    def update_device_status(self, ip_address: str, status: str) -> bool:
        """Update device status"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    UPDATE devices 
                    SET status = ?, last_seen = CURRENT_TIMESTAMP
                    WHERE ip_address = ?
                """, (status, ip_address))
                
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error updating device status: {e}")
            return False
    
    def update_device_throttle(self, ip_address: str, bandwidth_limit: str) -> bool:
        """Update device bandwidth limit"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    UPDATE devices 
                    SET bandwidth_limit = ?, status = 'throttled', last_seen = CURRENT_TIMESTAMP
                    WHERE ip_address = ?
                """, (bandwidth_limit, ip_address))
                
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error updating device throttle: {e}")
            return False
    
    def remove_device(self, ip_address: str) -> bool:
        """Remove device"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("DELETE FROM devices WHERE ip_address = ?", (ip_address,))
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error removing device: {e}")
            return False
    
    # ============================================================================
    # RULES MANAGEMENT
    # ============================================================================
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all rules"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT id, name, pattern, action, tags, applied_to, priority, 
                           status, description, hit_count, created_at, updated_at
                    FROM rules 
                    ORDER BY priority ASC, created_at DESC
                """)
                
                columns = [desc[0] for desc in cursor.description]
                rules = []
                
                for row in cursor.fetchall():
                    rule = dict(zip(columns, row))
                    # Parse tags JSON
                    if rule['tags']:
                        try:
                            rule['tags'] = json.loads(rule['tags'])
                        except:
                            rule['tags'] = []
                    else:
                        rule['tags'] = []
                    
                    # Convert timestamps
                    for time_field in ['created_at', 'updated_at']:
                        if rule[time_field]:
                            rule[time_field] = datetime.fromisoformat(rule[time_field])
                    
                    rules.append(rule)
                
                return rules
                
        except Exception as e:
            logger.error(f"Error getting rules: {e}")
            return []
    
    def add_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add new rule"""
        try:
            with self.get_cursor() as cursor:
                # Convert tags list to JSON string
                tags_json = json.dumps(rule_data.get('tags', []))
                
                cursor.execute("""
                    INSERT INTO rules (name, pattern, action, tags, applied_to, priority, status, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule_data['name'],
                    rule_data['pattern'],
                    rule_data['action'],
                    tags_json,
                    rule_data.get('applied_to', 'all'),
                    rule_data.get('priority', 100),
                    rule_data.get('status', 'on'),
                    rule_data.get('description', '')
                ))
                
                rule_id = cursor.lastrowid
                logger.info(f"Rule '{rule_data['name']}' added with ID {rule_id}")
                
                # Return the created rule
                return self.get_rule_by_id(rule_id)
                
        except Exception as e:
            logger.error(f"Error adding rule: {e}")
            raise
    
    def get_rule_by_id(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Get rule by ID"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT id, name, pattern, action, tags, applied_to, priority, 
                           status, description, hit_count, created_at, updated_at
                    FROM rules WHERE id = ?
                """, (rule_id,))
                
                row = cursor.fetchone()
                if row:
                    columns = [desc[0] for desc in cursor.description]
                    rule = dict(zip(columns, row))
                    
                    # Parse tags JSON
                    if rule['tags']:
                        try:
                            rule['tags'] = json.loads(rule['tags'])
                        except:
                            rule['tags'] = []
                    else:
                        rule['tags'] = []
                    
                    # Convert timestamps
                    for time_field in ['created_at', 'updated_at']:
                        if rule[time_field]:
                            rule[time_field] = datetime.fromisoformat(rule[time_field])
                    
                    return rule
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting rule {rule_id}: {e}")
            return None
    
    def update_rule(self, rule_id: int, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update existing rule"""
        try:
            with self.get_cursor() as cursor:
                # Build update query dynamically
                update_fields = []
                params = []
                
                for field, value in rule_data.items():
                    if field in ['name', 'pattern', 'action', 'applied_to', 'priority', 'status', 'description']:
                        update_fields.append(f"{field} = ?")
                        params.append(value)
                    elif field == 'tags':
                        update_fields.append("tags = ?")
                        params.append(json.dumps(value))
                
                if not update_fields:
                    return None
                
                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                params.append(rule_id)
                
                query = f"UPDATE rules SET {', '.join(update_fields)} WHERE id = ?"
                cursor.execute(query, params)
                
                if cursor.rowcount > 0:
                    logger.info(f"Rule {rule_id} updated")
                    return self.get_rule_by_id(rule_id)
                
                return None
                
        except Exception as e:
            logger.error(f"Error updating rule {rule_id}: {e}")
            return None
    
    def delete_rule(self, rule_id: int) -> bool:
        """Delete rule"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
                success = cursor.rowcount > 0
                
                if success:
                    logger.info(f"Rule {rule_id} deleted")
                
                return success
                
        except Exception as e:
            logger.error(f"Error deleting rule {rule_id}: {e}")
            return False
    
    def toggle_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
        """Toggle rule status"""
        try:
            with self.get_cursor() as cursor:
                # Get current status
                cursor.execute("SELECT status FROM rules WHERE id = ?", (rule_id,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                current_status = row[0]
                new_status = 'off' if current_status == 'on' else 'on'
                
                cursor.execute("""
                    UPDATE rules 
                    SET status = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (new_status, rule_id))
                
                if cursor.rowcount > 0:
                    logger.info(f"Rule {rule_id} toggled to {new_status}")
                    return self.get_rule_by_id(rule_id)
                
                return None
                
        except Exception as e:
            logger.error(f"Error toggling rule {rule_id}: {e}")
            return None
    
    # ============================================================================
    # LOGGING
    # ============================================================================
    
    def add_log(self, level: str, message: str, ip_address: str, **kwargs) -> bool:
        """Add log entry"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO logs (level, message, ip_address, url, user_agent, data_size)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    level,
                    message[:1000],  # Limit message length for Pi Zero W
                    ip_address,
                    kwargs.get('url'),
                    kwargs.get('user_agent'),
                    kwargs.get('data_size')
                ))
                
                return True
                
        except Exception as e:
            logger.error(f"Error adding log: {e}")
            return False
    
    def get_device_logs(self, ip_address: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get logs for specific device"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT timestamp, level, message, url, user_agent, data_size
                    FROM logs 
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (ip_address, limit))
                
                columns = [desc[0] for desc in cursor.description]
                logs = []
                
                for row in cursor.fetchall():
                    log = dict(zip(columns, row))
                    # Convert timestamp
                    if log['timestamp']:
                        log['timestamp'] = datetime.fromisoformat(log['timestamp'])
                    logs.append(log)
                
                return logs
                
        except Exception as e:
            logger.error(f"Error getting logs for {ip_address}: {e}")
            return []
    
    def get_device_logs_by_date(self, ip_address: str, date: str) -> List[Dict[str, Any]]:
        """Get logs for specific device and date"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("""
                    SELECT timestamp, level, message, url, user_agent, data_size
                    FROM logs 
                    WHERE ip_address = ? AND DATE(timestamp) = ?
                    ORDER BY timestamp DESC
                """, (ip_address, date))
                
                columns = [desc[0] for desc in cursor.description]
                logs = []
                
                for row in cursor.fetchall():
                    log = dict(zip(columns, row))
                    # Convert timestamp
                    if log['timestamp']:
                        log['timestamp'] = datetime.fromisoformat(log['timestamp'])
                    logs.append(log)
                
                return logs
                
        except Exception as e:
            logger.error(f"Error getting logs for {ip_address} on {date}: {e}")
            return []
    
    def get_total_logs_count(self) -> int:
        """Get total number of logs"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM logs")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting logs count: {e}")
            return 0
    
    # ============================================================================
    # MAINTENANCE (Pi Zero W specific)
    # ============================================================================
    
    def cleanup_old_logs(self, days: int = 30) -> int:
        """Clean up old logs to save space on Pi Zero W"""
        try:
            with self.get_cursor() as cursor:
                cutoff_date = datetime.now() - timedelta(days=days)
                cursor.execute("""
                    DELETE FROM logs 
                    WHERE timestamp < ?
                """, (cutoff_date.isoformat(),))
                
                deleted_count = cursor.rowcount
                logger.info(f"Cleaned up {deleted_count} old log entries")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error cleaning up old logs: {e}")
            return 0
    
    def vacuum_database(self) -> bool:
        """Optimize database (Pi Zero W specific)"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("VACUUM")
                cursor.execute("ANALYZE")
                cursor.execute("PRAGMA optimize")
                logger.info("Database optimized")
                return True
                
        except Exception as e:
            logger.error(f"Error optimizing database: {e}")
            return False
    
    def reset_database(self) -> bool:
        """Reset database to factory defaults (Router Reset)"""
        try:
            logger.warning("Database reset initiated")
            
            with self.get_cursor() as cursor:
                # Clear all data
                cursor.execute("DELETE FROM devices")
                cursor.execute("DELETE FROM rules")
                cursor.execute("DELETE FROM logs")
                
                # Reset admin password to default
                default_password_hash = self.get_password_hash("admin123")
                cursor.execute("""
                    UPDATE admins 
                    SET password_hash = ?, created_at = CURRENT_TIMESTAMP, last_login = NULL
                    WHERE username = 'admin'
                """, (default_password_hash,))
                
                # Commit changes
                self.conn.commit()
                
                logger.info("Database reset completed successfully")
                return True
                
        except Exception as e:
            logger.error(f"Error resetting database: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        try:
            if hasattr(self, 'conn'):
                self.conn.close()
                logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
    
    def __del__(self):
        """Cleanup on deletion"""
        self.close()
