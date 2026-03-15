#!/bin/bash

echo ""
echo "============================================================"
echo " Starting Secure ML Prediction API"
echo "============================================================"
echo ""

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -f venv/bin/activate ]; then
    source venv/bin/activate
fi

# Start the secure API
python security/SECURITY_6_secure_ml_api.py
