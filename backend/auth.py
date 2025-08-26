#!/usr/bin/env python3
"""
🔐 Target-Centric Admin Dashboard - Single Admin Authentication
Router-style login optimized for Raspberry Pi Zero W
"""

import os
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

class Auth:
    """Single admin authentication handler (router-style)"""
    
    def __init__(self, database):
        self.db = database
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # JWT configuration
        self.secret_key = os.getenv("SECRET_KEY", self._generate_secret_key())
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 1440  # 24 hours for router-style access
        
        # Rate limiting for Pi Zero W (prevent brute force)
        self.max_login_attempts = 3  # Stricter for single admin
        self.lockout_duration = 600  # 10 minutes lockout
        self._failed_attempts = 0
        self._lockout_until = None
        
        # Single admin credentials
        self.admin_username = os.getenv("ADMIN_USERNAME", "admin")
        self._ensure_single_admin()
    
    def _generate_secret_key(self) -> str:
        """Generate a secure secret key if none provided"""
        return secrets.token_urlsafe(32)
    
    def _ensure_single_admin(self):
        """Ensure only one admin exists and create default if none"""
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM admins")
                admin_count = cursor.fetchone()[0]
                
                if admin_count == 0:
                    # Create default admin
                    default_password = os.getenv("ADMIN_PASSWORD", "admin123")
                    self._create_default_admin(default_password)
                    logger.warning("⚠️ Default admin created: admin/admin123 - CHANGE THIS IMMEDIATELY!")
                elif admin_count > 1:
                    # Remove extra admins, keep only the first one
                    logger.warning("⚠️ Multiple admins detected, removing extras...")
                    self._cleanup_extra_admins()
                    
        except Exception as e:
            logger.error(f"Error ensuring single admin: {e}")
    
    def _create_default_admin(self, password: str):
        """Create the default admin user"""
        try:
            with self.db.get_cursor() as cursor:
                # Clear any existing admins
                cursor.execute("DELETE FROM admins")
                
                # Create single admin
                password_hash = self.get_password_hash(password)
                cursor.execute("""
                    INSERT INTO admins (username, password_hash, created_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (self.admin_username, password_hash))
                
                logger.info(f"Default admin '{self.admin_username}' created")
                
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
    
    def _cleanup_extra_admins(self):
        """Remove extra admin users, keep only the first one"""
        try:
            with self.db.get_cursor() as cursor:
                # Keep only the first admin
                cursor.execute("""
                    DELETE FROM admins 
                    WHERE id NOT IN (
                        SELECT MIN(id) FROM admins
                    )
                """)
                
                removed_count = cursor.rowcount
                if removed_count > 0:
                    logger.info(f"Removed {removed_count} extra admin users")
                    
        except Exception as e:
            logger.error(f"Error cleaning up extra admins: {e}")
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash"""
        try:
            return self.pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Password hashing error: {e}")
            # Fallback to simple hash for Pi Zero W compatibility
            return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username: str, password: str) -> str:
        """Authenticate admin user and return JWT token"""
        try:
            # Check if system is locked out
            if self._is_locked_out():
                raise Exception("System temporarily locked due to too many failed attempts. Please try again later.")
            
            # Only allow the configured admin username
            if username != self.admin_username:
                self._record_failed_attempt()
                raise Exception("Invalid username or password")
            
            # Verify credentials
            if not self._verify_credentials(password):
                self._record_failed_attempt()
                raise Exception("Invalid username or password")
            
            # Reset failed attempts on successful login
            self._reset_failed_attempts()
            
            # Generate access token
            access_token = self._create_access_token(
                data={"sub": username, "type": "admin", "single_admin": True}
            )
            
            # Update last login time
            self._update_last_login()
            
            logger.info(f"Admin '{username}' authenticated successfully")
            return access_token
            
        except Exception as e:
            logger.warning(f"Authentication failed for user '{username}': {e}")
            raise
    
    def _verify_credentials(self, password: str) -> bool:
        """Verify admin password"""
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("""
                    SELECT password_hash FROM admins WHERE username = ?
                """, (self.admin_username,))
                
                row = cursor.fetchone()
                if not row:
                    return False
                
                stored_hash = row[0]
                return self.verify_password(password, stored_hash)
                
        except Exception as e:
            logger.error(f"Error verifying credentials: {e}")
            return False
    
    def _create_access_token(self, data: Dict[str, Any]) -> str:
        """Create JWT access token"""
        try:
            to_encode = data.copy()
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
            to_encode.update({"exp": expire})
            
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            return encoded_jwt
            
        except Exception as e:
            logger.error(f"Error creating access token: {e}")
            raise
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token and return payload"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            username: str = payload.get("sub")
            token_type: str = payload.get("type")
            single_admin: bool = payload.get("single_admin", False)
            
            if username is None:
                raise Exception("Invalid token: missing username")
            
            if token_type != "admin":
                raise Exception("Invalid token: not an admin token")
            
            if not single_admin:
                raise Exception("Invalid token: not a single admin token")
            
            # Verify admin still exists and is the only one
            if not self._verify_single_admin():
                raise Exception("Invalid token: admin configuration changed")
            
            return payload
            
        except JWTError as e:
            logger.error(f"JWT verification error: {e}")
            raise Exception("Invalid token")
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise
    
    def _verify_single_admin(self) -> bool:
        """Verify that only one admin exists and it's the correct one"""
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM admins")
                admin_count = cursor.fetchone()[0]
                
                if admin_count != 1:
                    return False
                
                # Verify it's the correct admin
                cursor.execute("SELECT username FROM admins LIMIT 1")
                admin_username = cursor.fetchone()[0]
                
                return admin_username == self.admin_username
                
        except Exception as e:
            logger.error(f"Error verifying single admin: {e}")
            return False
    
    def _update_last_login(self) -> bool:
        """Update admin's last login time"""
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("""
                    UPDATE admins 
                    SET last_login = CURRENT_TIMESTAMP 
                    WHERE username = ?
                """, (self.admin_username,))
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Error updating last login: {e}")
            return False
    
    def _is_locked_out(self) -> bool:
        """Check if system is locked out"""
        if self._lockout_until and datetime.now() < self._lockout_until:
            return True
        return False
    
    def _record_failed_attempt(self) -> None:
        """Record a failed login attempt"""
        self._failed_attempts += 1
        
        if self._failed_attempts >= self.max_login_attempts:
            self._lockout_until = datetime.now() + timedelta(seconds=self.lockout_duration)
            logger.warning(f"System locked out for {self.lockout_duration} seconds due to {self._failed_attempts} failed attempts")
        else:
            logger.warning(f"Failed login attempt ({self._failed_attempts}/{self.max_login_attempts})")
    
    def _reset_failed_attempts(self) -> None:
        """Reset failed attempts"""
        self._failed_attempts = 0
        self._lockout_until = None
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change admin password"""
        try:
            # Verify old password
            if not self._verify_credentials(old_password):
                raise Exception("Invalid old password")
            
            # Hash new password
            new_hash = self.get_password_hash(new_password)
            
            # Update password in database
            with self.db.get_cursor() as cursor:
                cursor.execute("""
                    UPDATE admins 
                    SET password_hash = ? 
                    WHERE username = ?
                """, (new_hash, self.admin_username))
                
                if cursor.rowcount > 0:
                    logger.info(f"Admin password changed successfully")
                    return True
                else:
                    return False
                    
        except Exception as e:
            logger.error(f"Error changing admin password: {e}")
            raise
    
    def get_admin_info(self) -> Optional[Dict[str, Any]]:
        """Get admin user information"""
        try:
            with self.db.get_cursor() as cursor:
                cursor.execute("""
                    SELECT username, created_at, last_login
                    FROM admins 
                    WHERE username = ?
                """, (self.admin_username,))
                
                row = cursor.fetchone()
                if row:
                    columns = ['username', 'created_at', 'last_login']
                    admin_info = dict(zip(columns, row))
                    
                    # Convert timestamps
                    for time_field in ['created_at', 'last_login']:
                        if admin_info[time_field]:
                            admin_info[time_field] = datetime.fromisoformat(admin_info[time_field])
                    
                    return admin_info
                
                return None
                
        except Exception as e:
            logger.error(f"Error getting admin info: {e}")
            return None
    
    def get_lockout_status(self) -> Dict[str, Any]:
        """Get current lockout status"""
        return {
            'failed_attempts': self._failed_attempts,
            'max_attempts': self.max_login_attempts,
            'locked_out': self._is_locked_out(),
            'lockout_until': self._lockout_until.isoformat() if self._lockout_until else None,
            'remaining_attempts': max(0, self.max_login_attempts - self._failed_attempts)
        }
    
    def reset_lockout(self) -> bool:
        """Reset lockout (admin only, requires valid session)"""
        try:
            self._reset_failed_attempts()
            logger.info("System lockout reset by admin")
            return True
        except Exception as e:
            logger.error(f"Error resetting lockout: {e}")
            return False
    
    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens (Pi Zero W memory management)"""
        try:
            # This is a placeholder for token cleanup if needed
            # For now, JWT tokens are stateless and don't need cleanup
            return 0
        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {e}")
            return 0
