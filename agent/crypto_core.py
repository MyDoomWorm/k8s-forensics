import oqs
import hashlib
import json
import time
import sqlite3
import os
from pathlib import Path

DB_PATH = os.environ.get("FORENSICS_DB", "/tmp/forensics.db")
KEY_PATH = os.environ.get("FORENSICS_KEY", "/tmp/forensics_key.bin")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evidence_id TEXT UNIQUE,
        timestamp REAL,
        event_type TEXT,
        data TEXT,
        data_hash TEXT,
        prev_hash TEXT,
        signature BLOB,
        public_key BLOB,
        shred_status TEXT DEFAULT 'active'
    )''')
    conn.commit()
    conn.close()

def generate_or_load_keypair():
    if Path(KEY_PATH).exists():
        with open(KEY_PATH, 'rb') as f:
            pub_key = f.read()
        return pub_key
    sig = oqs.Signature('ML-DSA-65')
    pub_key = sig.generate_keypair()
    priv_key = sig.export_secret_key()
    with open(KEY_PATH, 'wb') as f:
        f.write(pub_key)
    with open(KEY_PATH + '.priv', 'wb') as f:
        f.write(priv_key)
    print(f"[crypto_core] Keypair generated, pubkey size: {len(pub_key)} bytes")
    return pub_key

def compute_hash(data: str) -> str:
    return hashlib.sha3_512(data.encode()).hexdigest()

def get_last_hash() -> str:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT data_hash FROM evidence ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    conn.close()
    return row[0] if row else "GENESIS"

def sign_evidence(event_type: str, data: dict) -> dict:
    data_str = json.dumps(data, sort_keys=True)
    data_hash = compute_hash(data_str)
    prev_hash = get_last_hash()
    chain_block = data_hash + prev_hash
    chain_hash = compute_hash(chain_block)

    with open(KEY_PATH + '.priv', 'rb') as f:
        priv_key = f.read()
    with open(KEY_PATH, 'rb') as f:
        pub_key = f.read()

    sig = oqs.Signature('ML-DSA-65', priv_key)
    signature = sig.sign(chain_hash.encode())

    evidence_id = f"ev-{int(time.time()*1000)}"
    timestamp = time.time()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO evidence
        (evidence_id, timestamp, event_type, data, data_hash, prev_hash, signature, public_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (evidence_id, timestamp, event_type, data_str,
         data_hash, prev_hash, signature, pub_key))
    conn.commit()
    conn.close()

    return {
        "evidence_id": evidence_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "data_hash": data_hash,
        "prev_hash": prev_hash,
        "signature_size": len(signature),
        "status": "signed"
    }

def verify_chain() -> list:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT evidence_id, data, data_hash, prev_hash, signature, public_key, shred_status FROM evidence ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()

    results = []
    prev_hash = "GENESIS"

    for row in rows:
        ev_id, data_str, data_hash, stored_prev, signature, pub_key, shred_status = row

        if shred_status == 'shredded':
            results.append({"evidence_id": ev_id, "status": "shredded", "chain_ok": True})
            prev_hash = data_hash
            continue

        computed_hash = compute_hash(data_str)
        hash_ok = computed_hash == data_hash
        chain_ok = stored_prev == prev_hash

        chain_block = data_hash + stored_prev
        chain_hash = compute_hash(chain_block)
        ver = oqs.Signature('ML-DSA-65', pub_key)
        try:
            sig_ok = ver.verify(chain_hash.encode(), signature, pub_key)
        except Exception:
            sig_ok = False

        results.append({
            "evidence_id": ev_id,
            "hash_ok": hash_ok,
            "chain_ok": chain_ok,
            "signature_ok": sig_ok,
            "status": "valid" if (hash_ok and chain_ok and sig_ok) else "TAMPERED"
        })
        prev_hash = data_hash

    return results

if __name__ == "__main__":
    init_db()
    generate_or_load_keypair()
    result = sign_evidence("test", {"message": "hello forensics"})
    print(json.dumps(result, indent=2))
    chain = verify_chain()
    print(json.dumps(chain, indent=2))
