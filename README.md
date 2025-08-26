# 🛡️ PiGuard Pro - Advanced Network Control Dashboard

> **Professional Network Security & Control Center for Raspberry Pi**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-Zero%20W-red.svg)](https://www.raspberrypi.org/products/raspberry-pi-zero-w/)

## 🎯 Overview

**PiGuard Pro** is a comprehensive, target-aware network control dashboard designed specifically for Raspberry Pi hotspots. It transforms your Pi into a professional-grade network security appliance with advanced device management, traffic filtering, and real-time monitoring capabilities.

### 🌟 Key Features

- **🖥️ Device Management**: Monitor, block, throttle, and control connected devices
- **🛡️ Advanced Security**: Per-device traffic filtering and content modification
- **📊 Real-time Monitoring**: Live system performance and network statistics
- **⚡ Pi Zero W Optimized**: Built specifically for resource-constrained environments
- **🔐 Single Admin System**: Router-style authentication with enhanced security
- **📱 Modern Dashboard**: Beautiful, responsive web interface
- **🔄 Dynamic Rules Engine**: On-the-fly traffic modification and filtering
- **💾 Persistent Storage**: SQLite database with automatic backups

## 🍓 Raspberry Pi Zero W Optimizations

This system is specifically designed for the **Raspberry Pi Zero W** with:
- **Single-core ARM11 processor** (1GHz) optimization
- **512MB RAM** memory management
- **MicroSD storage** I/O optimization
- **Built-in WiFi** (2.4GHz) hotspot configuration
- **Low power consumption** design
- **ARM-compatible** dependencies

### Performance Considerations
- Lightweight FastAPI backend
- SQLite database (no external DB server)
- Minimal memory footprint
- Efficient logging with rotation
- Background task optimization

## 🎯 System Overview

This system transforms your Raspberry Pi Zero W into a mission control center where every connected device is a target that can be:
- **Monitored**: Real-time traffic analysis and logging
- **Blocked**: Complete network access control
- **Throttled**: Bandwidth management per device
- **Redirected**: DNS and content redirection
- **Modified**: On-the-fly content injection and replacement

## 🆕 Latest Features (v2.0)

### 🔑 **Change Password System**
- **Secure password change** with current password verification
- **Password strength validation**: Minimum 8 characters, uppercase, lowercase, and number
- **Real-time validation** with user-friendly error messages
- **Dashboard integration** in Settings tab

### 🔄 **System Reset (Router Reset)**
- **Complete factory reset** functionality
- **Clears all settings**: devices, rules, logs, configurations
- **Resets admin password** to default (admin/admin123)
- **Creates backup** before reset
- **Confirmation dialogs** to prevent accidental resets

### 🚀 **Project Launcher**
- **Single-file launcher** (`project_launcher.py`) for complete project management
- **Component testing** for all system modules
- **Library updates** and dependency management
- **System health checks** with Pi Zero W specific monitoring
- **Process management** for backend and MitmProxy services

### 🌐 **Complete Web Dashboard**
- **Full-featured HTML dashboard** (`dashboard.html`) with Tailwind CSS
- **Real-time monitoring** with auto-refresh
- **Responsive design** optimized for mobile and desktop
- **Tabbed interface**: Overview, Devices, Rules, Logs, Settings
- **Interactive notifications** and status updates

## 🏗️ Core Features

### 1. Device Management
- Real-time device list (IP, MAC, Hostname)
- Data usage statistics per device
- Actions: Block/Unblock, Kick, Throttle
- Per-user traffic logs and analysis

### 2. Advanced Logging
- Structured logs per IP and date
- Browsing history and cookie tracking
- Searchable log viewer in dashboard
- **Pi Zero W optimized**: Log rotation and compression

### 3. Content Modification
- Image replacement
- Text substitution (e.g., "YouTube" → "StudyHub")
- Custom JavaScript injection
- Per-target application

### 4. DNS Filtering & Redirection
- Global and per-user filtering
- Import blocklists (EasyList, Pi-hole, Firebog, OISD)
- Custom redirection rules

### 5. Rules Management
- Full CRUD operations for filtering rules
- ON/OFF toggle for global filtering
- Tag-based organization
- Persistent storage in SQLite

### 6. Notifications & Alerts
- Real-time device connection alerts
- Suspicious activity detection
- Dashboard notifications

## 🗄️ Architecture

**PiGuard Pro** combines multiple technologies to create a robust network control system:

- **Backend**: FastAPI (Python) with async support
- **Database**: SQLite with optimized Pi Zero W settings
- **Proxy**: Mitmproxy for traffic interception and modification
- **Network Tools**: iptables, dnsmasq, tc for traffic control
- **Frontend**: Modern HTML/JavaScript with Tailwind CSS
- **Authentication**: JWT-based secure admin access

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HTML/JS      │    │   FastAPI       │    │   Network       │
│   Dashboard    │◄──►│   Backend       │◄──►│   Control      │
│                 │    │                 │    │   Layer        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   SQLite        │
                       │   Database      │
                       │                 │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Raspberry Pi Zero W (or compatible)
- MicroSD card (16GB+ recommended)
- Power supply (2.5A recommended)
- WiFi network for initial setup

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/RishuBurnwal/Raspberry-Pi-Advanced-chat-server.git
cd Raspberry-Pi-Advanced-chat-server
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the project launcher**
```bash
python project_launcher.py
```

4. **Access the dashboard**
   - Open your browser to `http://[PI_IP]:8080`
   - Login with default credentials: `admin` / `admin123`
   - **Important**: Change password immediately after first login

## 🔧 Configuration

**PiGuard Pro** uses environment variables for configuration. Copy `.env.example` to `.env` and modify:

```env
# Security
SECRET_KEY=your-super-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure-password

# Network Configuration
WIFI_INTERFACE=wlan0
BRIDGE_INTERFACE=br0
PI_ZERO_W=true

# Performance Settings
MAX_CONNECTIONS=10
MEMORY_LIMIT=400MB
WORKER_PROCESSES=1
```

### Pi Zero W Specific Settings
```env
# Performance tuning
WORKER_PROCESSES=1
MAX_REQUESTS=1000
LOG_LEVEL=INFO
ENABLE_DEBUG=false
COMPRESS_LOGS=true
```

### Network Setup
The system automatically configures:
- WiFi hotspot with hostapd (2.4GHz)
- DHCP server with dnsmasq
- iptables rules for traffic control
- Traffic shaping with tc
- **Optimized for Pi Zero W's single-core performance**

## 📊 Dashboard Features

### 🔐 **Authentication & Security**
- **Secure login** with JWT tokens
- **Change password** functionality with validation
- **Session management** with auto-logout
- **Secure logout** with token cleanup

### 📱 **Main Dashboard Tabs**
- **Overview**: Real-time system metrics (CPU, Memory, Devices, Rules)
- **Devices**: Connected device management and control
- **Rules**: Filtering rule creation and management
- **Logs**: System and device activity logs
- **Settings**: Password change and system reset

### 🎛️ **Device Control Actions**
- **Block/Unblock**: Complete network access control
- **Throttle**: Bandwidth limiting per device
- **Kick**: Disconnect devices from WiFi
- **Monitor**: Real-time traffic analysis

### ⚙️ **Rules Engine**
- **Create rules**: Pattern-based filtering
- **Edit rules**: Modify existing rules
- **Toggle rules**: Enable/disable filtering
- **Priority management**: Rule execution order

## 🛡️ Security Features

- **JWT-based authentication** with secure token storage
- **Encrypted password storage** using bcrypt
- **Password strength validation** (8+ chars, mixed case, numbers)
- **Network isolation** and traffic control
- **Audit logging** for all admin actions
- **Session management** with automatic cleanup

## 📝 API Endpoints

**PiGuard Pro** provides a comprehensive REST API:

### Authentication
- `POST /login` - Admin authentication
- `POST /change-password` - Update admin password
- `GET /admin-info` - Get admin user details

### Device Management
- `GET /devices` - List all connected devices
- `POST /device/block` - Block specific device
- `POST /device/unblock` - Unblock device
- `POST /device/throttle` - Throttle device bandwidth
- `POST /device/kick` - Disconnect device from WiFi

### System Control
- `GET /status` - System status and health
- `GET /performance` - Performance metrics
- `POST /reset-system` - Factory reset (Router Reset)

### Logs
- `GET /logs/{ip}` - Get logs for specific IP
- `GET /logs/{ip}/{date}` - Get logs for specific IP and date

### System (Pi Zero W specific)
- `GET /status` - System status and metrics
- `GET /stats` - System statistics
- `GET /performance` - Performance metrics
- `POST /reset-system` - Complete system reset ⭐ **NEW**

## 🔍 Monitoring & Logging

The system provides comprehensive logging optimized for Pi Zero W:
- Device connections/disconnections
- Traffic patterns and bandwidth usage
- Content filtering actions
- Rule application results
- System health metrics
- **Memory and CPU monitoring**
- **Temperature monitoring**
- **Log rotation and compression**

## 🚨 Troubleshooting

### Common Issues

**1. Service won't start**
```bash
# Check system resources
python project_launcher.py --health-check

# View detailed logs
python project_launcher.py --logs
```

**2. Dashboard not accessible**
- Verify backend is running on port 8080
- Check firewall settings
- Ensure WiFi interface is active

**3. Performance issues**
- Monitor memory usage with `htop`
- Check CPU temperature
- Verify MicroSD card health

### Logs Location
- System logs: `/var/log/hostapd/`
- Application logs: `logs/` directory
- Device logs: `logs/{ip}/` per device
- **System logs**: `/var/log/syslog`

## 🔧 Performance Tuning

### Memory Optimization
```bash
# Add to /boot/config.txt
gpu_mem=16
max_usb_current=1

# Add to /etc/sysctl.conf
vm.swappiness=10
vm.vfs_cache_pressure=50
```

### Storage Optimization
```bash
# Enable TRIM for SD card
sudo fstrim -v /

# Optimize SQLite
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=1000;
```

## 🚀 Project Launcher Features

The `project_launcher.py` provides a comprehensive management interface:

### 📋 **Main Menu Options**
1. **Start Complete Project** - Launch all services
2. **Test All Components** - Verify system integrity
3. **Update Libraries** - Update Python packages
4. **System Health Check** - Monitor Pi Zero W health
5. **View System Status** - Real-time metrics
6. **Reset All Settings** - Factory reset (Router Reset)
7. **Change Admin Password** - Secure password management
8. **View Logs** - System and application logs
9. **Configuration** - View current settings
10. **Open Dashboard** - Launch web interface
11. **Help & Troubleshooting** - Comprehensive guidance

### 🧪 **Component Testing**
- Database connectivity and schema
- Authentication system
- Network control tools
- Device monitoring
- Rules engine
- System monitoring
- API endpoints
- Configuration validation

### 🔧 **System Management**
- **Health monitoring**: CPU, memory, temperature, disk usage
- **Process management**: Backend and MitmProxy services
- **Log management**: View and analyze system logs
- **Configuration**: Environment variables and settings

## 🤝 Contributing

We welcome contributions to **PiGuard Pro**! Please read our contributing guidelines and submit pull requests.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly on Pi Zero W
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Copyright © 2025 Rishu Burnwal**

## 👨‍💻 Author & Maintainer

**Rishu Burnwal** - [GitHub Profile](https://github.com/RishuBurnwal)

**Rishu Burnwal** - [LinkedIn Profile](https://www.linkedin.com/in/rishuburnwal/)

- **Project**: PiGuard Pro - Advanced Network Control Dashboard
- **Repository**: [https://github.com/RishuBurnwal/PiGuard-Pro.git](https://github.com/RishuBurnwal/PiGuard-Pro.git)
- **Contact**: [GitHub Issues](https://github.com/RishuBurnwal/PiGuard-Pro/issues)

**PiGuard Pro** is actively maintained and regularly updated with new features and security improvements.

---

<div align="center">

**🛡️ PiGuard Pro** - *Professional Network Security for Raspberry Pi*

[![GitHub stars](https://img.shields.io/github/stars/RishuBurnwal/PiGuard-Pro?style=social)](https://github.com/RishuBurnwal/PiGuard-Pro)
[![GitHub forks](https://img.shields.io/github/forks/RishuBurnwal/PiGuard-Pro?style=social)](https://github.com/RishuBurnwal/PiGuard-Pro)

</div>
