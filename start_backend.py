#!/usr/bin/env python3
"""
🚀 Target-Centric Admin Dashboard - Backend Startup Script
Optimized for Raspberry Pi Zero W
"""

import os
import sys
import logging
import uvicorn
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

# Import configuration
from config import (
    HOST, PORT, WORKERS, RELOAD, LOG_LEVEL,
    validate_config, get_config_summary
)

def setup_logging():
    """Setup logging configuration"""
    try:
        # Create logs directory
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, LOG_LEVEL.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/startup.log'),
                logging.StreamHandler()
            ]
        )
        
        logger = logging.getLogger(__name__)
        logger.info("🚀 Starting Target-Centric Admin Dashboard Backend...")
        
        return logger
        
    except Exception as e:
        print(f"❌ Failed to setup logging: {e}")
        return None

def check_environment():
    """Check environment requirements"""
    try:
        logger = logging.getLogger(__name__)
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.error("❌ Python 3.8+ required")
            return False
        
        # Check if running on Pi Zero W (optional)
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpu_info = f.read()
                if 'BCM2835' in cpu_info or 'BCM2836' in cpu_info:
                    logger.info("🍓 Raspberry Pi detected - applying optimizations")
                else:
                    logger.info("💻 Non-Pi system detected - some optimizations may not apply")
        except:
            logger.info("💻 Could not detect system type")
        
        # Check required directories
        required_dirs = ['logs', 'scripts']
        for dir_name in required_dirs:
            Path(dir_name).mkdir(exist_ok=True)
            logger.debug(f"✅ Directory {dir_name} ready")
        
        # Check database directory
        db_dir = Path("backend")
        if not db_dir.exists():
            logger.error("❌ Backend directory not found")
            return False
        
        logger.info("✅ Environment check passed")
        return True
        
    except Exception as e:
        logger.error(f"❌ Environment check failed: {e}")
        return False

def main():
    """Main startup function"""
    try:
        # Setup logging
        logger = setup_logging()
        if not logger:
            print("❌ Failed to setup logging")
            sys.exit(1)
        
        # Check environment
        if not check_environment():
            logger.error("❌ Environment check failed")
            sys.exit(1)
        
        # Validate configuration
        config_validation = validate_config()
        if config_validation['warnings']:
            for warning in config_validation['warnings']:
                logger.warning(warning)
        
        # Log configuration summary
        config_summary = get_config_summary()
        logger.info("⚙️ Configuration loaded:")
        for section, settings in config_summary.items():
            logger.info(f"  {section}: {settings}")
        
        # Check if running as root (for network control)
        if os.geteuid() == 0:
            logger.warning("⚠️ Running as root - network control features will be available")
        else:
            logger.warning("⚠️ Not running as root - network control features may be limited")
        
        # Start the server
        logger.info(f"🌐 Starting server on {HOST}:{PORT}")
        logger.info(f"🔧 Workers: {WORKERS}, Reload: {RELOAD}")
        
        uvicorn.run(
            "backend.main:app",
            host=HOST,
            port=PORT,
            workers=WORKERS,
            reload=RELOAD,
            log_level=LOG_LEVEL.lower(),
            access_log=True
        )
        
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server startup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
