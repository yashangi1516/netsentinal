import os
import pickle
import numpy as np
import torch
import torch.nn as nn

try:
    from .model_train import Autoencoder
except ImportError:
    from models.model_train import Autoencoder

class ThreatDetector:
    """
    ThreatDetector loads Isolation Forest and PyTorch Autoencoder models
    and provides real-time threat evaluation for network feature vectors.
    """
    def __init__(self):
        models_dir = os.path.dirname(__file__)
        scaler_path = os.path.join(models_dir, "scaler.pkl")
        if_path = os.path.join(models_dir, "isolation_forest.pkl")
        ae_path = os.path.join(models_dir, "autoencoder.pth")
        
        # Load Scaler
        if os.path.exists(scaler_path):
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)
        else:
            self.scaler = None
            print("[Warning] Scaler file not found. Inference will run unscaled.")
            
        # Load Isolation Forest
        if os.path.exists(if_path):
            with open(if_path, "rb") as f:
                self.if_model = pickle.load(f)
        else:
            self.if_model = None
            print("[Warning] Isolation Forest model file not found.")
            
        # Load Autoencoder
        if os.path.exists(ae_path):
            checkpoint = torch.load(ae_path, map_location=torch.device("cpu"))
            self.ae_model = Autoencoder(checkpoint.get("input_dim", 10))
            self.ae_model.load_state_dict(checkpoint["state_dict"])
            self.ae_model.eval()
            self.ae_threshold = checkpoint["threshold"]
        else:
            self.ae_model = None
            self.ae_threshold = 0.5
            print("[Warning] Autoencoder model file not found.")
            
    def predict(self, feature_vector):
        """
        Runs prediction on a single 10-dimensional feature vector.
        
        Returns:
            dict containing:
                - isolation_forest_score: anomaly score from IF (lower means more anomalous)
                - isolation_forest_label: 1 (normal) or -1 (anomaly)
                - autoencoder_reconstruction_error: MSE of reconstruction
                - autoencoder_label: 0 (normal) or 1 (anomaly)
                - threat_level: 'Normal', 'Low', 'Medium', 'High'
                - threat_score: raw normalized threat index from 0 to 100
                - severity_color: CSS color matching threat level
        """
        # Convert to numpy array shape (1, 10)
        x = np.array(feature_vector, dtype=float).reshape(1, -1)
        
        # Apply scaling
        if self.scaler is not None:
            try:
                x_scaled = self.scaler.transform(x)
            except Exception:
                x_scaled = x
        else:
            x_scaled = x
            
        # 1. Isolation Forest Inference
        if_score = 0.0
        if_anomaly = 1  # 1 = normal, -1 = anomaly
        if self.if_model is not None:
            # decision_function outputs values where lower/negative values are anomalies
            if_score = float(self.if_model.decision_function(x_scaled)[0])
            if_anomaly = int(self.if_model.predict(x_scaled)[0])
            
        # 2. Autoencoder Inference
        ae_error = 0.0
        ae_anomaly = 0  # 0 = normal, 1 = anomaly
        if self.ae_model is not None:
            with torch.no_grad():
                x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
                x_reconstructed = self.ae_model(x_tensor)
                ae_error = float(torch.mean((x_reconstructed - x_tensor) ** 2).item())
                if ae_error > self.ae_threshold:
                    ae_anomaly = 1
                    
        # 3. Decision Logic & Severity Computation
        # Map raw scores to an unified threat score 0 - 100
        # For IF: typical scores are -0.5 to +0.5. Map lower scores to higher threat.
        if_threat_contrib = max(0, min(100, (0.2 - if_score) * 120))
        
        # For AE: map reconstruction error relation to threshold
        ratio = ae_error / max(1e-5, self.ae_threshold)
        ae_threat_contrib = max(0, min(100, ratio * 30))
        
        # Weighted threat score
        threat_score = 0.4 * if_threat_contrib + 0.6 * ae_threat_contrib
        
        # Enforce higher severity if both models tag it as anomaly
        is_if_anom = (if_anomaly == -1)
        is_ae_anom = (ae_anomaly == 1)
        
        if is_if_anom and is_ae_anom:
            threat_level = "High"
            severity_color = "#ef4444"  # Red
            threat_score = max(80.0, threat_score)
        elif is_if_anom or is_ae_anom:
            if threat_score > 50:
                threat_level = "Medium"
                severity_color = "#f97316"  # Orange
            else:
                threat_level = "Low"
                severity_color = "#eab308"  # Yellow
        else:
            threat_level = "Normal"
            severity_color = "#22c55e"  # Green
            threat_score = min(20.0, threat_score)
            
        return {
            "isolation_forest_score": if_score,
            "isolation_forest_label": if_anomaly,
            "autoencoder_reconstruction_error": ae_error,
            "autoencoder_label": ae_anomaly,
            "threat_level": threat_level,
            "threat_score": float(round(threat_score, 2)),
            "severity_color": severity_color
        }
