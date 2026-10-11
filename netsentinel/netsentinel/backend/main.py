import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import asyncio
import json

try:
    from .schemas import PredictRequest, PredictResponse, TopologyResponse
    from .database import init_db, get_alerts, get_topology
    from .capture import start_capture, stop_capture
    from ..models.model_predict import ThreatDetector
except ImportError:
    from backend.schemas import PredictRequest, PredictResponse, TopologyResponse
    from backend.database import init_db, get_alerts, get_topology
    from backend.capture import start_capture, stop_capture
    from models.model_predict import ThreatDetector

app = FastAPI(title="NetSentinel API", version="1.0.0")

# Enable CORS for frontend flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[WebSocket] Connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"[WebSocket] Disconnected. Active connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        
        # Build JSON message string
        payload = json.dumps(message)
        
        # Broadcast to all clients
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                disconnected.append(connection)
                
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()
detector = None

async def broadcast_wrapper(data):
    """Callback wrapped to route packet event messages from the background thread to WebSockets."""
    await manager.broadcast(data)

@app.on_event("startup")
async def startup_event():
    global detector
    # Initialize DB connection (handles fallback gracefully)
    await init_db()
    
    # Preload the inference models
    detector = ThreatDetector()
    
    # Start packet sniffer / simulated pipeline
    start_capture(broadcast_wrapper)
    print("[Startup] API and packet engines loaded successfully.")

@app.on_event("shutdown")
def shutdown_event():
    # Stop background tasks
    stop_capture()
    print("[Shutdown] Cleaned up background threads.")

# --- API Endpoints ---

@app.get("/alerts")
async def get_alerts_endpoint(limit: int = 50):
    """Retrieve the latest network anomalies and alerts."""
    alerts = await get_alerts(limit)
    return alerts

@app.get("/topology", response_model=TopologyResponse)
async def get_topology_endpoint():
    """Retrieve the current network connection topology nodes and edges."""
    topology = await get_topology()
    return topology

@app.post("/predict", response_model=PredictResponse)
async def predict_endpoint(request: PredictRequest):
    """
    On-demand AI intrusion detection endpoint.
    Accepts 10-dimensional feature vector, returns isolation forest & autoencoder prediction reports.
    """
    global detector
    if detector is None:
        detector = ThreatDetector()
        
    try:
        prediction = detector.predict(request.features)
        return prediction
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference failed: {str(e)}")

# --- WebSockets ---

@app.websocket("/ws/packets")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint streaming raw live packet metadata and alerts."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection open and listen for any client messages (ping/configs)
            data = await websocket.receive_text()
            # Respond to ping messages
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WebSocket Exception] {e}")
        manager.disconnect(websocket)

# --- Serve Static UI Files ---

# Resolve frontend directory path relative to project structure
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
    
    @app.get("/", response_class=HTMLResponse)
    async def get_index():
        index_file = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return HTMLResponse("<h2>NetSentinel UI Index page not found in frontend directory.</h2>")
else:
    print(f"[Warning] Frontend directory not found at {FRONTEND_DIR}. API only mode enabled.")
