from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from datetime import datetime
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "securemind"

client = None
db = None

def connect():
    global client, db
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        db = client[DB_NAME]
        print(f"[SecureMind] MongoDB connected: {MONGO_URI}")
        return True
    except ConnectionFailure as e:
        print(f"[SecureMind] MongoDB connection failed: {e}")
        return False

def get_collection(name: str):
    if db is None:
        connect()
    return db[name] if db is not None else None

def save_scan(scan_data: dict):
    col = get_collection("scans")
    if col is None:
        return None
    scan_data["created_at"] = datetime.utcnow()
    result = col.insert_one(scan_data)
    return str(result.inserted_id)

def get_recent_scans(limit: int = 50):
    col = get_collection("scans")
    if col is None:
        return []
    return list(col.find({}, {"_id": 0}).sort("created_at", -1).limit(limit))

def get_threat_stats():
    col = get_collection("scans")
    if col is None:
        return {}
    total = col.count_documents({})
    blocked = col.count_documents({"verdict": "BLOCKED"})
    flagged = col.count_documents({"verdict": "FLAGGED"})
    safe = col.count_documents({"verdict": "PASSED"})
    pipeline = [{"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}]
    by_type = {d["_id"]: d["count"] for d in col.aggregate(pipeline)}
    return {
        "total": total,
        "blocked": blocked,
        "flagged": flagged,
        "safe": safe,
        "by_attack_type": by_type
    }

def close():
    global client
    if client:
        client.close()
        print("[SecureMind] MongoDB connection closed.")

if __name__ == "__main__":
    if connect():
        print("Stats:", get_threat_stats())
    close()
