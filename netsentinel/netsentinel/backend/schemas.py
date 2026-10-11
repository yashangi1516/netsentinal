from pydantic import BaseModel, Field
from typing import List, Optional

class PredictRequest(BaseModel):
    features: List[float] = Field(..., min_items=10, max_items=10, description="10-dimensional numerical feature vector")

class PredictResponse(BaseModel):
    isolation_forest_score: float
    isolation_forest_label: int
    autoencoder_reconstruction_error: float
    autoencoder_label: int
    threat_level: str
    threat_score: float
    severity_color: str

class Alert(BaseModel):
    timestamp: float
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    protocol: str
    size: int
    threat_level: str
    threat_score: float
    anomaly_reason: str
    severity_color: str

class TopologyNode(BaseModel):
    id: str
    label: str
    type: str = "device"
    last_active: float
    anomaly: Optional[bool] = False

class TopologyEdge(BaseModel):
    id: str
    source: str
    target: str
    last_active: float
    severity: str = "Normal"

class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
