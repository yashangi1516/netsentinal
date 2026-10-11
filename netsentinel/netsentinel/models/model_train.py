import os
import pickle
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

# Ensure output directory exists
os.makedirs(os.path.dirname(__file__), exist_ok=True)

# 1. Define the Autoencoder Architecture
class Autoencoder(nn.Module):
    def __init__(self, input_dim=10):
        super(Autoencoder, self).__init__()
        # Encoder: Compress features
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.ReLU()
        )
        # Decoder: Reconstruct features
        self.decoder = nn.Sequential(
            nn.Linear(4, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim)
        )
        
    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def generate_synthetic_normal_data(n_samples=5000):
    """
    Generates synthetic 'normal' network traffic patterns.
    Normal traffic has typical sizes, ports, and protocols.
    Features order:
    1. Size, 2. Proto, 3. Src IP, 4. Dst IP, 5. TTL, 6. Flags, 7. Src Port, 8. Dst Port, 9. Inter-arrival, 10. Entropy
    """
    np.random.seed(42)
    
    # Packet sizes (mostly 60 to 1500 bytes)
    sizes = np.random.normal(500, 200, n_samples)
    sizes = np.clip(sizes, 40, 1500)
    
    # Protocols (mostly TCP=6, some UDP=17, very few ICMP=1)
    protos = np.random.choice([6, 17, 1], size=n_samples, p=[0.75, 0.22, 0.03])
    
    # IP Addresses (simulated as 32-bit integers in typical local or popular web ranges)
    # Local range 192.168.1.0/24 -> 3232235776 to 3232236031
    src_ips = np.random.randint(3232235776, 3232236031, size=n_samples, dtype=np.int64)
    dst_ips = np.random.randint(3232235776, 3232236031, size=n_samples, dtype=np.int64)
    
    # TTL (mostly 64, 128, or 255)
    ttls = np.random.choice([64, 128, 255], size=n_samples, p=[0.6, 0.3, 0.1])
    
    # TCP Flags (mostly ACK=16, PSH+ACK=24, SYN=2)
    flags = np.random.choice([16, 24, 2, 0], size=n_samples, p=[0.7, 0.2, 0.05, 0.05])
    # Clear flags for non-TCP protocols
    flags[protos != 6] = 0
    
    # Ports (standard HTTP/HTTPS 80/443, local high ports, DNS 53)
    src_ports = np.random.choice([80, 443, 53, 3000, 8080], size=n_samples)
    # Add random ephemeral ports
    ephemeral_mask = np.random.rand(n_samples) > 0.5
    src_ports[ephemeral_mask] = np.random.randint(49152, 65535, size=np.sum(ephemeral_mask))
    
    dst_ports = np.random.choice([80, 443, 53, 3000, 8080], size=n_samples)
    ephemeral_mask = np.random.rand(n_samples) > 0.5
    dst_ports[ephemeral_mask] = np.random.randint(49152, 65535, size=np.sum(ephemeral_mask))
    # Clear ports for ICMP
    src_ports[protos == 1] = 0
    dst_ports[protos == 1] = 0
    
    # Inter-arrival times (mostly small, exponential-like distribution)
    inter_arrivals = np.random.exponential(scale=0.1, size=n_samples)
    
    # Payload byte entropy (low to medium for standard files/requests: 1.5 to 5.0)
    entropies = np.random.uniform(1.0, 5.0, size=n_samples)
    entropies[protos == 1] = 0.0  # ICMP typically 0 entropy or very low
    
    # Assemble feature matrix
    X = np.column_stack((
        sizes, protos, src_ips, dst_ips, ttls, flags, src_ports, dst_ports, inter_arrivals, entropies
    ))
    return X

def train_models():
    print("Generating synthetic normal traffic data...")
    X_train = generate_synthetic_normal_data(6000)
    
    # 2. Fit and Save the Standard Scaler
    print("Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    scaler_path = os.path.join(os.path.dirname(__file__), "scaler.pkl")
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)
    print(f"Scaler saved to {scaler_path}")
    
    # 3. Train and Save the Isolation Forest Model
    print("Training Isolation Forest...")
    # Contamination set to 0.03 representing estimated noise/anomalies in training data
    clf = IsolationForest(n_estimators=150, contamination=0.03, random_state=42)
    clf.fit(X_train_scaled)
    
    if_path = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
    with open(if_path, "wb") as f:
        pickle.dump(clf, f)
    print(f"Isolation Forest saved to {if_path}")
    
    # 4. Train the PyTorch Autoencoder
    print("Training PyTorch Autoencoder...")
    input_dim = X_train_scaled.shape[1]
    model = Autoencoder(input_dim)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    
    epochs = 20
    batch_size = 64
    dataset_size = len(X_train_scaled)
    
    model.train()
    for epoch in range(epochs):
        # Shuffle training set
        indices = np.arange(dataset_size)
        np.random.shuffle(indices)
        X_shuffled = X_train_scaled[indices]
        
        epoch_loss = 0.0
        for i in range(0, dataset_size, batch_size):
            batch = X_shuffled[i : i + batch_size]
            batch_tensor = torch.tensor(batch, dtype=torch.float32)
            
            # Forward pass
            outputs = model(batch_tensor)
            loss = criterion(outputs, batch_tensor)
            
            # Backward and optimize
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item() * len(batch)
            
        print(f"Epoch [{epoch+1}/{epochs}], Loss: {epoch_loss / dataset_size:.6f}")
        
    # Evaluate reconstruction error on training dataset to define an anomaly threshold
    model.eval()
    with torch.no_grad():
        X_tensor = torch.tensor(X_train_scaled, dtype=torch.float32)
        reconstructions = model(X_tensor)
        mse = torch.mean((reconstructions - X_tensor) ** 2, dim=1).numpy()
        
    # Set threshold at 95th percentile of normal reconstruction error
    threshold = float(np.percentile(mse, 95))
    print(f"Autoencoder Anomaly Threshold (95th percentile of normal): {threshold:.6f}")
    
    # Save the model state dict and threshold together
    model_state = {
        "state_dict": model.state_dict(),
        "threshold": threshold,
        "input_dim": input_dim
    }
    
    ae_path = os.path.join(os.path.dirname(__file__), "autoencoder.pth")
    torch.save(model_state, ae_path)
    print(f"Autoencoder model saved to {ae_path}")
    print("Model training successfully completed!")

if __name__ == "__main__":
    train_models()
