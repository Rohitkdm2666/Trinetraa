#!/bin/bash
# run_all.sh — Start all services
# Run from: /home/rohit_kadam/Workspace/EDI/final_project/project/

PROJECT_DIR="/home/rohit_kadam/Workspace/EDI/final_project/project"
VENV="$PROJECT_DIR/venv/bin/activate"
DASHBOARD_DIR="$PROJECT_DIR/dashboard"

echo "🚀 Starting AEGIS Cyber Defense System..."

# Kill existing processes
fuser -k 8000/tcp 2>/dev/null
echo "[✓] Cleared port 8000"

# Terminal 1 — FastAPI
gnome-terminal --title="FastAPI Backend" -- bash -c "
  cd $PROJECT_DIR &&
  source $VENV &&
  uvicorn main:app --host 0.0.0.0 --port 8000 --reload;
  exec bash"

echo "[✓] FastAPI starting..."
sleep 3  # wait for FastAPI to be ready

# Terminal 2 — Predictor
gnome-terminal --title="Predictor" -- bash -c "
  cd $PROJECT_DIR &&
  source $VENV &&
  python3 predictor.py;
  exec bash"

echo "[✓] Predictor starting..."
sleep 1

# Terminal 3 — React Dashboard
gnome-terminal --title="Dashboard" -- bash -c "
  cd $DASHBOARD_DIR &&
  npm start;
  exec bash"

echo "[✓] Dashboard starting..."
echo ""
echo "✅ All services launched!"
echo "   Backend   → http://localhost:8000"
echo "   Dashboard → http://localhost:3000"
echo "   API Docs  → http://localhost:8000/docs"
echo ""
echo "To simulate attacks:"
echo "   sudo nmap -sS 192.168.1.1"
echo "   sudo hping3 -S --flood -p 80 192.168.1.1"