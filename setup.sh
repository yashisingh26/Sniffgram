#!/bin/bash

echo ""
echo "────────────────────────────────────────────"
echo "🛠️  Sniffgram Installer by Yashi Singh"
echo "────────────────────────────────────────────"

# Step 1: Update APT and install system dependencies
echo "📦 Installing system packages (tshark, venv)..."
sudo apt update && sudo apt install -y tshark libpcap-dev python3-venv

# Step 2: Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv

# Step 3: Activate and install Python dependencies
echo "📥 Installing Python packages..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Step 4: Run the tool
echo "🚀 Starting Sniffgram..."
sudo ./venv/bin/python Sniffgram.py
