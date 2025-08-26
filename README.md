# 🚀 Target-Centric Admin Dashboard for Raspberry Pi Zero W

A comprehensive network control center optimized for Raspberry Pi Zero W that treats every connected device as a target for monitoring, filtering, and content modification. **Now with complete change password functionality and system reset capabilities!**

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
- **Raspberry Pi Zero W** with WiFi capability
- **Raspberry Pi OS Lite** (recommended for headless operation)
- Python 3.8+ (included in Pi OS)
- **Root access** for network commands
- **MicroSD card** (16GB+ recommended)

### Installation

#### Option 1: Using Project Launcher (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd raspberry-pi-hostapd

# Run the project launcher
sudo python3 project_launcher.py

# Follow the interactive menu:
# 1. Test all components
# 2. Update libraries
# 3. Start complete project
```

#### Option 2: Manual Setup
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3-pip python3-venv hostapd dnsmasq iptables-persistent

# Create virtual environment (saves space)
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Start backend
cd backend
python main.py
```

### Access Dashboard
- **URL**: `http://[PI_IP]:8000`
- **Default credentials**: `admin` / `admin123`
- **Change password immediately** after first login!

## 🔧 Configuration

### Environment Variables
Create `.env` file:
```env
SECRET_KEY=your-secret-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure-password
WIFI_INTERFACE=wlan0
BRIDGE_INTERFACE=br0
PI_ZERO_W=true
MAX_CONNECTIONS=10
MEMORY_LIMIT=400MB
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

### Authentication
- `POST /login` - Admin login
- `POST /change-password` - Change admin password ⭐ **NEW**
- `GET /admin-info` - Get admin information ⭐ **NEW**

### Devices
- `GET /devices` - List all devices
- `POST /device/block` - Block device
- `POST /device/unblock` - Unblock device
- `POST /device/throttle` - Throttle bandwidth
- `POST /device/kick` - Disconnect device

### Rules
- `GET /rules` - List all rules
- `POST /rules/add` - Add new rule
- `POST /rules/update/{id}` - Update rule
- `DELETE /rules/delete/{id}` - Delete rule
- `POST /rules/toggle/{id}` - Toggle rule status

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

### Pi Zero W Specific Issues
1. **Low memory**: Monitor RAM usage, enable swap if needed
2. **Slow performance**: Check CPU temperature, ensure proper cooling
3. **WiFi issues**: Verify 2.4GHz compatibility
4. **SD card corruption**: Use high-quality SD cards, enable journaling

### Common Issues
1. **Permission denied**: Ensure scripts run with sudo
2. **Interface not found**: Check WiFi interface name in config
3. **Database errors**: Verify SQLite file permissions
4. **Password change fails**: Ensure new password meets requirements

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

This is a comprehensive network control system optimized for Raspberry Pi Zero W. Contributions welcome for:
- Additional filtering rules
- UI improvements
- Network protocol support
- Performance optimizations
- **Pi Zero W specific optimizations**
- **Security enhancements**
- **Dashboard features**

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

The project is licensed under the MIT License, which provides:
- **Freedom to use** for any purpose (commercial or personal)
- **Freedom to modify** and adapt the code
- **Freedom to distribute** copies of the software
- **No warranty** or liability protection
- **Attribution requirement** for the original copyright notice

**⚠️ Important**: This software provides powerful network control capabilities. Users are responsible for complying with local laws and regulations regarding network monitoring and content filtering.

---

**⚠️ Warning**: This system provides powerful network control capabilities. Use responsibly and ensure compliance with local laws and regulations regarding network monitoring and content filtering.

**🍓 Pi Zero W Note**: This system is specifically optimized for Raspberry Pi Zero W's hardware constraints. For production use, consider using a Pi 3 or Pi 4 for better performance with more devices.

**🔑 Security Note**: Always change the default password (admin/admin123) immediately after installation. The system includes robust password validation and secure storage mechanisms.

**🔄 Reset Warning**: The system reset functionality will clear ALL data and settings. Use only when absolutely necessary and ensure you have backups of important configurations.
