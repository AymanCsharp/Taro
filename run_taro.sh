#!/bin/bash

echo "Starting Taro Web Vulnerability Scanner..."
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python3 is not installed. Please install Python3 first."
    exit 1
fi

# Check if requirements are installed
if [ ! -f "requirements.txt" ]; then
    echo "Error: requirements.txt not found. Please ensure you're in the correct directory."
    exit 1
fi

# Install requirements if not already installed
echo "Installing/checking Python dependencies..."
pip3 install -r requirements.txt

# Run the scanner
echo ""
echo "Running Taro Scanner..."
python3 taro_scanner.py
