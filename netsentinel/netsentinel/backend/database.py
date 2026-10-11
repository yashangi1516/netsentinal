import os
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure

# MongoDB connection string
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "netsentinel"

client = None
db = None
use_fallback = False

# Mock in-memory database fallback to guarantee smooth execution without local MongoDB
_mock_db = {
    "packets_raw": [],
    "anomalies": [],
    "topology_nodes": {},
    "topology_edges": {},
    "alerts": []
}

async def init_db():
    global client, db, use_fallback
    try:
        # Create Mongo Client with short timeout (2s) to prevent blocking
        client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=2000)
        # Verify connection
        await client.admin.command('ping')
        db = client[DB_NAME]
        use_fallback = False
        print(f"[Database] Successfully connected to MongoDB at {MONGO_URI}")
    except Exception as e:
        use_fallback = True
        db = None
        print(f"[Database] Warning: Could not connect to MongoDB ({e}). Using in-memory fallback database.")

async def insert_packet(packet_data):
    if use_fallback:
        _mock_db["packets_raw"].append(packet_data)
        if len(_mock_db["packets_raw"]) > 500:
            _mock_db["packets_raw"].pop(0)
    else:
        try:
            await db.packets_raw.insert_one(packet_data)
        except Exception as e:
            print(f"[Database Error] insert_packet: {e}")

async def insert_anomaly(anomaly_data):
    if use_fallback:
        _mock_db["anomalies"].append(anomaly_data)
        if len(_mock_db["anomalies"]) > 500:
            _mock_db["anomalies"].pop(0)
    else:
        try:
            await db.anomalies.insert_one(anomaly_data)
        except Exception as e:
            print(f"[Database Error] insert_anomaly: {e}")

async def insert_alert(alert_data):
    if use_fallback:
        _mock_db["alerts"].append(alert_data)
        if len(_mock_db["alerts"]) > 200:
            _mock_db["alerts"].pop(0)
    else:
        try:
            await db.alerts.insert_one(alert_data)
        except Exception as e:
            print(f"[Database Error] insert_alert: {e}")

async def update_topology(src_ip, dst_ip, severity="Normal"):
    """
    Updates the topology nodes and edges.
    Nodes represent unique devices (IPs).
    Edges represent connections between source and destination.
    """
    node_src = {"id": src_ip, "label": src_ip, "type": "device", "last_active": asyncio.get_event_loop().time()}
    node_dst = {"id": dst_ip, "label": dst_ip, "type": "device", "last_active": asyncio.get_event_loop().time()}
    
    edge_id = f"{src_ip}->{dst_ip}"
    edge = {
        "id": edge_id,
        "source": src_ip,
        "target": dst_ip,
        "last_active": asyncio.get_event_loop().time(),
        "severity": severity
    }
    
    if use_fallback:
        # Source Node
        if src_ip not in _mock_db["topology_nodes"]:
            _mock_db["topology_nodes"][src_ip] = node_src
        _mock_db["topology_nodes"][src_ip]["last_active"] = node_src["last_active"]
        if severity == "High":
            _mock_db["topology_nodes"][src_ip]["anomaly"] = True
            
        # Destination Node
        if dst_ip not in _mock_db["topology_nodes"]:
            _mock_db["topology_nodes"][dst_ip] = node_dst
        _mock_db["topology_nodes"][dst_ip]["last_active"] = node_dst["last_active"]
        
        # Edge
        _mock_db["topology_edges"][edge_id] = edge
    else:
        try:
            # Update Source Node
            update_fields = {"last_active": node_src["last_active"]}
            if severity == "High":
                update_fields["anomaly"] = True
            await db.topology_nodes.update_one(
                {"id": src_ip},
                {"$set": update_fields, "$setOnInsert": {"label": src_ip, "type": "device"}},
                upsert=True
            )
            
            # Update Destination Node
            await db.topology_nodes.update_one(
                {"id": dst_ip},
                {"$set": {"last_active": node_dst["last_active"]}, "$setOnInsert": {"label": dst_ip, "type": "device"}},
                upsert=True
            )
            
            # Update Edge
            await db.topology_edges.update_one(
                {"id": edge_id},
                {"$set": edge},
                upsert=True
            )
        except Exception as e:
            print(f"[Database Error] update_topology: {e}")

async def get_alerts(limit=50):
    if use_fallback:
        # Return sorted list reverse
        return sorted(_mock_db["alerts"], key=lambda x: x.get("timestamp", 0), reverse=True)[:limit]
    else:
        try:
            cursor = db.alerts.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            print(f"[Database Error] get_alerts: {e}")
            return []

async def get_topology():
    if use_fallback:
        return {
            "nodes": list(_mock_db["topology_nodes"].values()),
            "edges": list(_mock_db["topology_edges"].values())
        }
    else:
        try:
            nodes_cursor = db.topology_nodes.find({}, {"_id": 0})
            edges_cursor = db.topology_edges.find({}, {"_id": 0})
            nodes = await nodes_cursor.to_list(length=1000)
            edges = await edges_cursor.to_list(length=1000)
            return {"nodes": nodes, "edges": edges}
        except Exception as e:
            print(f"[Database Error] get_topology: {e}")
            return {"nodes": [], "edges": []}
