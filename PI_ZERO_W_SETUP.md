# 🍓 Raspberry Pi Zero W Setup Guide

## 🎯 Overview

This guide will help you set up PiGuard Pro - Advanced Network Control Dashboard on your Raspberry Pi Zero W. The system is specifically optimized for the Pi Zero W's hardware constraints (512MB RAM, single-core ARM11 processor).

## 📋 Prerequisites

- Raspberry Pi Zero W
- MicroSD card (8GB+ recommended, Class 10)
- Power supply (5V/2.5A recommended)
- Ethernet cable (for initial setup)
- USB keyboard and HDMI cable (optional, for headless setup)

## 🚀 Initial Pi Zero W Setup

### 1. Flash Raspberry Pi OS

```bash
# Download Raspberry Pi OS Lite (recommended for Pi Zero W)
wget https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2023-05-03/2023-05-03-raspios-bullseye-armhf-lite.img.xz

# Flash to SD card (replace /dev/sdX with your SD card device)
sudo dd if=2023-05-03-raspios-bullseye-armhf-lite.img.xz of=/dev/sdX bs=4M status=progress
```

### 2. Enable SSH and WiFi (Headless Setup)

Create `wpa_supplicant.conf` and `ssh` files in the boot partition:

```bash
# wpa_supplicant.conf
country=US
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="YOUR_WIFI_SSID"
    psk="YOUR_WIFI_PASSWORD"
    key_mgmt=WPA-PSK
}
```

### 3. Boot and Connect

```bash
# Insert SD card and power on Pi Zero W
# Wait 2-3 minutes for first boot
# Find Pi's IP address on your network
nmap -sn 192.168.1.0/24

# SSH into Pi
ssh pi@192.168.1.XXX
# Default password: raspberry
```

## 🔧 System Preparation

### 1. Update System

```bash
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
sudo apt autoclean
```

### 2. Install Required Packages

```bash
# Essential packages
sudo apt install -y python3 python3-pip python3-venv git curl wget

# Network tools
sudo apt install -y hostapd dnsmasq iptables-persistent

# Development tools (optional)
sudo apt install -y vim nano htop
```

### 3. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv hotspot-env
source hotspot-env/bin/activate

# Install requirements
pip install -r requirements.txt

# Make virtual environment persistent
echo "source /home/pi/hotspot-dashboard/hotspot-env/bin/activate" >> ~/.bashrc
```

## 🌐 WiFi Hotspot Configuration

### 1. Configure hostapd

```bash
sudo nano /etc/hostapd/hostapd.conf
```

Add this configuration:

```ini
# WiFi Hotspot Configuration for Pi Zero W
interface=wlan0
driver=nl80211
ssid=PiHotspot
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=your_hotspot_password
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
max_num_sta=10
```

### 2. Configure dnsmasq

```bash
sudo nano /etc/dnsmasq.conf
```

Add this configuration:

```ini
# DHCP Configuration
interface=wlan0
dhcp-range=192.168.50.10,192.168.50.100,24h
dhcp-option=3,192.168.50.1
dhcp-option=6,192.168.50.1
server=8.8.8.8
server=8.8.4.4
```

### 3. Configure Network Interfaces

```bash
sudo nano /etc/network/interfaces
```

Add this configuration:

```ini
# WiFi Interface
allow-hotplug wlan0
iface wlan0 inet static
    address 192.168.50.1
    netmask 255.255.255.0
    network 192.168.50.0
    broadcast 192.168.50.255

# Bridge Interface (if using ethernet)
auto br0
iface br0 inet dhcp
    bridge_ports eth0
    bridge_stp off
    bridge_waitport 0
    bridge_fd 0
```

### 4. Enable IP Forwarding

```bash
sudo nano /etc/sysctl.conf
```

Add this line:

```ini
net.ipv4.ip_forward=1
```

Apply changes:

```bash
sudo sysctl -p
```

### 5. Configure iptables

```bash
sudo nano /etc/iptables/rules.v4
```

Add basic rules:

```bash
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT

*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A FORWARD -i wlan0 -o eth0 -j ACCEPT
-A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
COMMIT
```

## 🚀 Deploy the Dashboard

### 1. Clone Repository

```bash
cd /home/pi
git clone https://github.com/your-repo/hotspot-dashboard.git
cd hotspot-dashboard
```

### 2. Configure Environment

```bash
# Create environment file
nano .env
```

Add your configuration:

```bash
# Admin credentials (CHANGE THESE!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password_here
SECRET_KEY=your_random_secret_key_here

# Network settings
WIFI_INTERFACE=wlan0
BRIDGE_INTERFACE=br0
GATEWAY_IP=192.168.50.1
DHCP_START=192.168.50.10
DHCP_END=192.168.50.100

# Pi Zero W optimizations
MAX_CONNECTIONS=10
MAX_DEVICES=10
WORKERS=1
ENABLE_QOS=true
```

### 3. Install as System Service

```bash
# Copy service file
sudo cp hotspot-dashboard.service /etc/systemd/system/

# Edit service file with your paths
sudo nano /etc/systemd/system/hotspot-dashboard.service

# Update paths and credentials
WorkingDirectory=/home/pi/hotspot-dashboard
Environment=ADMIN_PASSWORD=your_secure_password_here
Environment=SECRET_KEY=your_secret_key_here

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable hotspot-dashboard
sudo systemctl start hotspot-dashboard

# Check status
sudo systemctl status hotspot-dashboard
```

## 🔍 Testing and Verification

### 1. Check Service Status

```bash
# Check if service is running
sudo systemctl status hotspot-dashboard

# Check logs
sudo journalctl -u hotspot-dashboard -f

# Check if port is listening
sudo netstat -tlnp | grep :8000
```

### 2. Test WiFi Hotspot

```bash
# Connect to PiHotspot WiFi network
# Try to get IP address
# Check if internet works

# Monitor connections
sudo hostapd_cli -i wlan0 all_sta
```

### 3. Access Dashboard

```bash
# Open browser and go to:
http://192.168.50.1:8000

# Login with:
Username: admin
Password: your_secure_password_here
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Service Won't Start

```bash
# Check logs
sudo journalctl -u hotspot-dashboard -n 50

# Check Python path
python3 -c "import sys; print(sys.path)"

# Check dependencies
pip list | grep fastapi
```

#### 2. WiFi Not Working

```bash
# Check hostapd status
sudo systemctl status hostapd

# Check interface
ip addr show wlan0

# Restart networking
sudo systemctl restart networking
```

#### 3. Dashboard Not Accessible

```bash
# Check firewall
sudo iptables -L

# Check if port is open
sudo netstat -tlnp | grep :8000

# Test locally
curl http://localhost:8000
```

### Performance Monitoring

```bash
# Monitor system resources
htop

# Check memory usage
free -h

# Check disk usage
df -h

# Monitor network
iftop -i wlan0
```

## 🔒 Security Considerations

### 1. Change Default Passwords

```bash
# Change Pi user password
passwd

# Change admin dashboard password
# Use the web interface or update .env file
```

### 2. Firewall Configuration

```bash
# Install ufw
sudo apt install ufw

# Configure basic firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8000
sudo ufw enable
```

### 3. Regular Updates

```bash
# Set up automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## 📊 Performance Optimization

### 1. Memory Management

```bash
# Monitor memory usage
watch -n 1 free -h

# Add swap if needed
sudo fallocate -l 512M /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

### 2. Database Optimization

```bash
# The system automatically optimizes SQLite for Pi Zero W
# Monitor database size
ls -lh hotspot_control.db

# Clean old logs if needed
# This happens automatically every 30 days
```

### 3. Network Optimization

```bash
# Monitor network performance
sudo tc -s qdisc show dev wlan0

# Check for network bottlenecks
sudo iotop
```

## 🚀 Production Deployment

### 1. Environment Variables

```bash
# Create production environment file
sudo nano /etc/environment

# Add production settings
HOTSPOT_DASHBOARD_ENV=production
HOTSPOT_DASHBOARD_DEBUG=false
```

### 2. Log Rotation

```bash
# Configure logrotate
sudo nano /etc/logrotate.d/hotspot-dashboard

# Add configuration
/home/pi/hotspot-dashboard/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 pi pi
}
```

### 3. Backup Strategy

```bash
# Create backup script
nano /home/pi/backup_dashboard.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/home/pi/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
cp /home/pi/hotspot-dashboard/hotspot_control.db $BACKUP_DIR/dashboard_$DATE.db
cp /home/pi/hotspot-dashboard/.env $BACKUP_DIR/env_$DATE

# Keep only last 7 backups
find $BACKUP_DIR -name "dashboard_*.db" -mtime +7 -delete
find $BACKUP_DIR -name "env_*" -mtime +7 -delete
```

## 📱 Mobile Access

### 1. Port Forwarding (Optional)

If you want to access the dashboard from outside your network:

```bash
# Configure router to forward port 8000 to Pi Zero W
# External Port: 8000
# Internal IP: 192.168.50.1
# Internal Port: 8000
```

### 2. Dynamic DNS (Optional)

```bash
# Install ddclient for dynamic DNS updates
sudo apt install ddclient

# Configure with your DDNS provider
sudo nano /etc/ddclient.conf
```

## 🎉 Success!

Your Raspberry Pi Zero W is now running a fully functional Target-Centric Admin Dashboard! 

### What You Can Do:

- ✅ Monitor connected devices in real-time
- ✅ Block/unblock specific devices
- ✅ Throttle bandwidth for selected devices
- ✅ Create content filtering rules
- ✅ View detailed traffic logs
- ✅ Manage WiFi hotspot settings

### Next Steps:

1. **Customize Rules**: Add your own filtering rules
2. **Monitor Performance**: Watch system resources
3. **Scale Up**: Add more devices as needed
4. **Security**: Regularly update passwords and monitor logs

### Support:

- Check logs: `sudo journalctl -u hotspot-dashboard -f`
- Restart service: `sudo systemctl restart hotspot-dashboard`
- View status: `sudo systemctl status hotspot-dashboard`

Happy monitoring! 🎯📊
