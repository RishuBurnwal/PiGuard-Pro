# 📋 Changelog

All notable changes to **PiGuard Pro** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2024-12-19

### 🎉 **Major Rebranding: PiGuard Pro**
- **Project renamed** from "Target-Centric Admin Dashboard" to "PiGuard Pro"
- **New branding** with professional shield icon and modern design
- **Updated all documentation** to reflect new project identity
- **Enhanced README.md** with badges, better structure, and professional presentation

### 🔧 **Updated Files**
- `README.md` - Complete rebranding and enhanced documentation
- `project_launcher.py` - Updated banner and branding
- `hotspot-dashboard.service` - Updated service description and paths
- `PROJECT_SUMMARY.md` - Updated project title and references
- `PI_ZERO_W_SETUP.md` - Updated setup guide branding
- `start_backend.py` - Updated startup messages
- `backend/main.py` - Updated backend branding
- `dashboard.html` - Updated frontend branding

### 📁 **New Files**
- `CHANGELOG.md` - This changelog file (NEW)

## [2.0.0] - 2024-12-19

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

### 📊 **System Monitoring**
- **Real-time metrics**: CPU, memory, temperature, disk usage
- **Performance optimization** for Pi Zero W
- **Health monitoring** with alerts and notifications
- **Resource usage tracking** and optimization

## [1.0.0] - 2024-12-01

### 🎯 **Initial Release**
- **FastAPI backend** with comprehensive API endpoints
- **SQLite database** with Pi Zero W optimizations
- **Device management** system with monitoring and control
- **Rules engine** for traffic filtering and modification
- **MitmProxy integration** for content modification
- **Network control** with iptables, dnsmasq, and tc
- **Authentication system** with JWT tokens
- **Basic logging** and monitoring capabilities

### 🍓 **Pi Zero W Optimizations**
- **Single-core ARM11** processor optimization
- **512MB RAM** memory management
- **MicroSD storage** I/O optimization
- **Built-in WiFi** (2.4GHz) hotspot configuration
- **Low power consumption** design
- **ARM-compatible** dependencies

---

## 🔄 **Migration Notes**

### From v1.0.0 to v2.0.0
- **New authentication endpoints** for password management
- **System reset functionality** for factory defaults
- **Enhanced dashboard** with real-time monitoring
- **Project launcher** for simplified management

### From v2.0.0 to v2.1.0
- **Project rebranding** to PiGuard Pro
- **Updated file paths** and service names
- **Enhanced documentation** and branding
- **Professional presentation** and structure

---

## 📝 **Contributing to Changelog**

When adding new features or fixes, please update this changelog following the format above:

1. **Add new version** at the top
2. **Use clear categories**: Added, Changed, Deprecated, Removed, Fixed, Security
3. **Include issue numbers** if applicable
4. **Update version** in other files (README.md, etc.)

---

**🛡️ PiGuard Pro** - *Professional Network Security for Raspberry Pi*

**Copyright © 2024-2025 Rishu Burnwal**
