#!/bin/bash
cd /opt/literary-magazine
git pull origin master
pkill -9 -f "python app.py" 2>/dev/null
pkill -9 -f "python3 app.py" 2>/dev/null
sleep 1
source venv/bin/activate
nohup venv/bin/python app.py > /dev/null 2>&1 &
echo "Deployed at $(date)"
