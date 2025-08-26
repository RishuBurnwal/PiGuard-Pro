#!/usr/bin/env python3
"""
⚙️ Target-Centric Admin Dashboard - Rules Engine
Rule processing and application for Pi Zero W
"""

import os
import logging
import asyncio
import time
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

class RulesEngine:
    """Rules engine for processing and applying filtering rules"""
    
    def __init__(self, database, mitmproxy_controller, network_control):
        self.db = database
        self.mitmproxy = mitmproxy_controller
        self.network_control = network_control
        self.processing = False
        self.process_task = None
        self._lock = threading.Lock()
        
        # Pi Zero W specific settings
        self.processing_interval = int(os.getenv("RULES_PROCESSING_INTERVAL", "60"))  # seconds
        self.max_rules = int(os.getenv("MAX_RULES", "100"))
        self.enable_rule_caching = os.getenv("ENABLE_RULE_CACHING", "true").lower() == "true"
        
        # Rule cache
        self.rule_cache = {}
        self.cache_last_update = 0
        self.cache_ttl = 300  # 5 minutes cache TTL
        
        # Rule statistics
        self.rule_stats = {}
    
    async def start_processing(self):
        """Start rules processing"""
        try:
            if self.processing:
                logger.info("Rules processing is already running")
                return
            
            self.processing = True
            logger.info("⚙️ Starting rules engine...")
            
            # Start processing task
            self.process_task = asyncio.create_task(self._processing_loop())
            
            logger.info("✅ Rules engine started successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to start rules engine: {e}")
            self.processing = False
    
    async def stop_processing(self):
        """Stop rules processing"""
        try:
            if not self.processing:
                return
            
            logger.info("🛑 Stopping rules engine...")
            
            self.processing = False
            
            if self.process_task:
                self.process_task.cancel()
                try:
                    await self.process_task
                except asyncio.CancelledError:
                    pass
            
            logger.info("✅ Rules engine stopped")
            
        except Exception as e:
            logger.error(f"Error stopping rules engine: {e}")
    
    async def _processing_loop(self):
        """Main processing loop"""
        try:
            while self.processing:
                # Process rules
                await self._process_rules()
                
                # Update rule statistics
                await self._update_rule_statistics()
                
                # Clean up old statistics
                await self._cleanup_old_statistics()
                
                # Wait for next processing cycle
                await asyncio.sleep(self.processing_interval)
                
        except asyncio.CancelledError:
            logger.info("Rules processing cancelled")
        except Exception as e:
            logger.error(f"Error in processing loop: {e}")
            self.processing = False
    
    async def _process_rules(self):
        """Process and apply rules"""
        try:
            # Get active rules
            rules = self._get_active_rules()
            
            # Apply rules to network control
            await self._apply_network_rules(rules)
            
            # Apply rules to mitmproxy
            await self._apply_mitmproxy_rules(rules)
            
            # Update rule cache
            self._update_rule_cache(rules)
            
            logger.debug(f"Processed {len(rules)} active rules")
            
        except Exception as e:
            logger.error(f"Error processing rules: {e}")
    
    def _get_active_rules(self) -> List[Dict[str, Any]]:
        """Get active rules from database"""
        try:
            # Check cache first
            if self.enable_rule_caching:
                current_time = time.time()
                if current_time - self.cache_last_update < self.cache_ttl and self.rule_cache:
                    return list(self.rule_cache.values())
            
            # Get fresh rules from database
            rules = self.db.get_rules()
            
            # Filter active rules
            active_rules = [rule for rule in rules if rule['status'] == 'on']
            
            # Sort by priority
            active_rules.sort(key=lambda x: x['priority'])
            
            return active_rules
            
        except Exception as e:
            logger.error(f"Error getting active rules: {e}")
            return []
    
    def _update_rule_cache(self, rules: List[Dict[str, Any]]):
        """Update rule cache"""
        try:
            with self._lock:
                self.rule_cache = {rule['id']: rule for rule in rules}
                self.cache_last_update = time.time()
                
        except Exception as e:
            logger.error(f"Error updating rule cache: {e}")
    
    async def _apply_network_rules(self, rules: List[Dict[str, Any]]):
        """Apply rules to network control layer"""
        try:
            for rule in rules:
                if rule['action'] in ['block', 'redirect']:
                    # Apply DNS-level rules
                    await self._apply_dns_rule(rule)
                    
        except Exception as e:
            logger.error(f"Error applying network rules: {e}")
    
    async def _apply_dns_rule(self, rule: Dict[str, Any]):
        """Apply DNS-level rule"""
        try:
            pattern = rule['pattern']
            action = rule['action']
            applied_to = rule['applied_to']
            
            if action == 'block':
                # Block domain using network_control
                if self.network_control:
                    success = self.network_control.add_dns_rule(pattern, 'block')
                    if success:
                        logger.info(f"DNS block rule applied for {pattern}")
                    else:
                        logger.error(f"Failed to apply DNS block rule for {pattern}")
                    
            elif action == 'redirect':
                # Redirect domain using network_control
                if '→' in pattern:
                    domain, target = pattern.split('→', 1)
                    domain = domain.strip()
                    target = target.strip()
                    
                    if self.network_control:
                        success = self.network_control.add_dns_rule(domain, 'redirect', target)
                        if success:
                            logger.info(f"DNS redirect rule applied for {domain} to {target}")
                        else:
                            logger.error(f"Failed to apply DNS redirect rule for {domain}")
                        
        except Exception as e:
            logger.error(f"Error applying DNS rule: {e}")
    
    async def _apply_mitmproxy_rules(self, rules: List[Dict[str, Any]]):
        """Apply rules to mitmproxy"""
        try:
            # Reload mitmproxy rules if needed
            if self._rules_changed(rules):
                if self.mitmproxy and hasattr(self.mitmproxy, 'reload_rules'):
                    self.mitmproxy.reload_rules()
                    logger.info("MitmProxy rules reloaded")
                    
        except Exception as e:
            logger.error(f"Error applying mitmproxy rules: {e}")
    
    def _rules_changed(self, current_rules: List[Dict[str, Any]]) -> bool:
        """Check if rules have changed"""
        try:
            if not self.rule_cache:
                return True
            
            # Compare rule counts
            if len(current_rules) != len(self.rule_cache):
                return True
            
            # Compare rule content
            for rule in current_rules:
                rule_id = rule['id']
                if rule_id not in self.rule_cache:
                    return True
                
                cached_rule = self.rule_cache[rule_id]
                if (rule['pattern'] != cached_rule['pattern'] or 
                    rule['action'] != cached_rule['action'] or
                    rule['status'] != cached_rule['status']):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking rule changes: {e}")
            return True
    
    async def _update_rule_statistics(self):
        """Update rule usage statistics"""
        try:
            # This is a placeholder for rule statistics
            # In a real implementation, you'd track rule hits and performance
            
            for rule in self._get_active_rules():
                rule_id = rule['id']
                
                if rule_id not in self.rule_stats:
                    self.rule_stats[rule_id] = {
                        'hits': 0,
                        'last_hit': None,
                        'performance': 0.0
                    }
                    
        except Exception as e:
            logger.error(f"Error updating rule statistics: {e}")
    
    async def _cleanup_old_statistics(self):
        """Clean up old rule statistics"""
        try:
            # Remove statistics for deleted rules
            current_rule_ids = {rule['id'] for rule in self._get_active_rules()}
            
            with self._lock:
                stats_to_remove = []
                for rule_id in self.rule_stats:
                    if rule_id not in current_rule_ids:
                        stats_to_remove.append(rule_id)
                
                for rule_id in stats_to_remove:
                    del self.rule_stats[rule_id]
                    
                if stats_to_remove:
                    logger.debug(f"Cleaned up statistics for {len(stats_to_remove)} removed rules")
                    
        except Exception as e:
            logger.error(f"Error cleaning up old statistics: {e}")
    
    def reload_rules(self):
        """Reload rules immediately"""
        try:
            if self.processing:
                # Force immediate processing
                asyncio.create_task(self._process_rules())
                logger.info("Rules reload initiated")
            else:
                logger.warning("Cannot reload rules - engine not running")
                
        except Exception as e:
            logger.error(f"Error reloading rules: {e}")
    
    def get_rule_statistics(self, rule_id: Optional[int] = None) -> Dict[str, Any]:
        """Get rule statistics"""
        try:
            if rule_id:
                # Return specific rule stats
                return self.rule_stats.get(rule_id, {})
            else:
                # Return all rule stats
                return self.rule_stats.copy()
                
        except Exception as e:
            logger.error(f"Error getting rule statistics: {e}")
            return {}
    
    def get_engine_status(self) -> Dict[str, Any]:
        """Get rules engine status"""
        try:
            status = {
                'processing': self.processing,
                'processing_interval': self.processing_interval,
                'max_rules': self.max_rules,
                'rule_caching': self.enable_rule_caching,
                'cached_rules': len(self.rule_cache),
                'active_rules': len([r for r in self._get_active_rules() if r['status'] == 'on']),
                'total_rules': len(self.db.get_rules()),
                'cache_last_update': self.cache_last_update,
                'rule_statistics': len(self.rule_stats)
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting engine status: {e}")
            return {'processing': False, 'error': str(e)}
    
    def validate_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate rule data"""
        try:
            errors = []
            warnings = []
            
            # Check required fields
            required_fields = ['name', 'pattern', 'action']
            for field in required_fields:
                if not rule_data.get(field):
                    errors.append(f"Missing required field: {field}")
            
            # Validate pattern
            pattern = rule_data.get('pattern', '')
            if pattern:
                if len(pattern) > 500:
                    errors.append("Pattern too long (max 500 characters)")
                
                # Check for potentially problematic patterns
                if pattern.startswith('*') and len(pattern) < 3:
                    warnings.append("Very broad pattern - may affect many URLs")
            
            # Validate action
            action = rule_data.get('action', '')
            valid_actions = ['block', 'redirect', 'throttle', 'modify', 'alert']
            if action and action not in valid_actions:
                errors.append(f"Invalid action: {action}. Must be one of: {', '.join(valid_actions)}")
            
            # Validate priority
            priority = rule_data.get('priority', 100)
            if not isinstance(priority, int) or priority < 1 or priority > 1000:
                errors.append("Priority must be between 1 and 1000")
            
            # Validate applied_to
            applied_to = rule_data.get('applied_to', 'all')
            if applied_to != 'all' and not self._is_valid_ip(applied_to):
                warnings.append("Applied_to should be 'all' or a valid IP address")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors,
                'warnings': warnings
            }
            
        except Exception as e:
            logger.error(f"Error validating rule: {e}")
            return {
                'valid': False,
                'errors': [f"Validation error: {e}"],
                'warnings': []
            }
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def get_rule_suggestions(self, rule_type: str = None) -> List[Dict[str, Any]]:
        """Get rule suggestions based on type"""
        try:
            suggestions = []
            
            if rule_type == 'block' or not rule_type:
                suggestions.extend([
                    {
                        'name': 'Block Social Media',
                        'pattern': 'facebook.com',
                        'action': 'block',
                        'description': 'Block Facebook access',
                        'tags': ['social', 'distraction']
                    },
                    {
                        'name': 'Block Video Sites',
                        'pattern': 'youtube.com',
                        'action': 'block',
                        'description': 'Block YouTube access',
                        'tags': ['video', 'entertainment']
                    },
                    {
                        'name': 'Block Ads',
                        'pattern': 'ads.',
                        'action': 'block',
                        'description': 'Block common ad domains',
                        'tags': ['ads', 'privacy']
                    }
                ])
            
            if rule_type == 'redirect' or not rule_type:
                suggestions.extend([
                    {
                        'name': 'Study Mode Redirect',
                        'pattern': 'youtube.com → studyhub.local',
                        'action': 'redirect',
                        'description': 'Redirect YouTube to study resources',
                        'tags': ['study', 'redirect']
                    }
                ])
            
            if rule_type == 'throttle' or not rule_type:
                suggestions.extend([
                    {
                        'name': 'Video Throttling',
                        'pattern': '*.mp4',
                        'action': 'throttle',
                        'description': 'Slow down video content',
                        'tags': ['video', 'bandwidth']
                    }
                ])
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Error getting rule suggestions: {e}")
            return []
    
    def export_rules(self, format_type: str = 'json') -> str:
        """Export rules in specified format"""
        try:
            rules = self.db.get_rules()
            
            if format_type == 'json':
                return json.dumps(rules, indent=2, default=str)
            elif format_type == 'csv':
                # Simple CSV export
                if not rules:
                    return ""
                
                headers = list(rules[0].keys())
                csv_lines = [','.join(headers)]
                
                for rule in rules:
                    row = []
                    for header in headers:
                        value = rule.get(header, '')
                        if isinstance(value, (list, dict)):
                            value = json.dumps(value)
                        row.append(str(value))
                    csv_lines.append(','.join(row))
                
                return '\n'.join(csv_lines)
            else:
                raise ValueError(f"Unsupported export format: {format_type}")
                
        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
            return ""
    
    def import_rules(self, rules_data: str, format_type: str = 'json') -> Dict[str, Any]:
        """Import rules from data"""
        try:
            imported_count = 0
            errors = []
            
            if format_type == 'json':
                rules = json.loads(rules_data)
            else:
                raise ValueError(f"Unsupported import format: {format_type}")
            
            for rule in rules:
                try:
                    # Validate rule
                    validation = self.validate_rule(rule)
                    if not validation['valid']:
                        errors.append(f"Rule '{rule.get('name', 'Unknown')}': {', '.join(validation['errors'])}")
                        continue
                    
                    # Add rule to database
                    self.db.add_rule(rule)
                    imported_count += 1
                    
                except Exception as e:
                    errors.append(f"Rule '{rule.get('name', 'Unknown')}': {e}")
            
            return {
                'success': True,
                'imported': imported_count,
                'errors': errors,
                'total_rules': len(rules)
            }
            
        except Exception as e:
            logger.error(f"Error importing rules: {e}")
            return {
                'success': False,
                'imported': 0,
                'errors': [str(e)],
                'total_rules': 0
            }
