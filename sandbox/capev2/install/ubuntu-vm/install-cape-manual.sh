#!/bin/bash

set -e

echo "=== CAPEv2 Manual Installation ==="

# 1. System packages
echo "[1] Installing system packages..."
sudo apt update
sudo apt install -y python3 python3-pip python3-dev \
  libpq-dev postgresql postgresql-contrib \
  build-essential libssl-dev libffi-dev git curl wget

# 2. Python dependencies
echo "[2] Installing Python dependencies..."
cd /opt/CAPEv2
pip3 install --upgrade pip setuptools wheel poetry
poetry install
pip3 install malduck yara-python

# 3. PostgreSQL
echo "[3] Setting up PostgreSQL..."
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo -u postgres psql <<EOF
CREATE USER cape WITH PASSWORD 'cape';
CREATE DATABASE cuckoo OWNER cape;
GRANT ALL PRIVILEGES ON DATABASE cuckoo TO cape;
EOF

# 4. Configuration
echo "[4] Creating configuration files..."
cp conf/cuckoo.conf.default conf/cuckoo.conf
cp conf/auxiliary.conf.default conf/auxiliary.conf
cp conf/vmware.conf.default conf/vmware.conf

# 5. Database init
echo "[5] Initializing database..."
python3 cuckoo.py -c conf/cuckoo.conf createdb

# 6. VMware Tools
echo "[6] Installing VMware Tools..."
sudo apt install -y open-vm-tools open-vm-tools-desktop
sudo mkdir -p /mnt/hgfs
echo '.host:/  /mnt/hgfs  fuse.vmhgfs-fuse  allow_other,uid=1000,gid=1000  0  0' | sudo tee -a /etc/fstab

# 7. Services
echo "[7] Setting up systemd services..."
sudo tee /etc/systemd/system/cape.service > /dev/null <<EOF
[Unit]
Description=CAPE Sandbox
After=network.target

[Service]
Type=simple
User=kali
WorkingDirectory=/opt/CAPEv2
ExecStart=/usr/bin/python3 /opt/CAPEv2/cuckoo.py -c /opt/CAPEv2/conf/cuckoo.conf
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/cape-web.service > /dev/null <<EOF
[Unit]
Description=CAPE Web Interface
After=network.target cape.service

[Service]
Type=simple
User=kali
WorkingDirectory=/opt/CAPEv2
ExecStart=/usr/bin/python3 /opt/CAPEv2/web/manage.py runserver 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cape cape-web

echo "[✓] CAPEv2 installation complete!"
echo "Start services: sudo systemctl start cape cape-web"
echo "Web interface: http://192.168.100.10:8000"
