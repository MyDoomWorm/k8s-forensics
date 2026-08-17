import sqlite3
import hashlib
import json
import time
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from crypto_core import DB_PATH, KEY_PATH, sign_evidence, compute_hash

def get_evidence_by_id(evidence_id: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise ValueError(f"Evidence {evidence_id} not found")
    columns = ['id', 'evidence_id', 'timestamp', 'event_type', 'data',
               'data_hash', 'prev_hash', 'signature', 'public_key', 'shred_status']
    return dict(zip(columns, row))

def shred_evidence(evidence_id: str, reason: str = "retention_expired", authorized_by: str = "system") -> dict:

    evidence = get_evidence_by_id(evidence_id)

    if evidence['shred_status'] == 'shredded':
        return {"status": "already_shredded", "evidence_id": evidence_id}

    original_hash = evidence['data_hash']

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        UPDATE evidence
        SET data = '[SHREDDED]',
            shred_status = 'shredded'
        WHERE evidence_id = ?
    """, (evidence_id,))
    conn.commit()
    conn.close()

    tombstone_data = {
        "type": "shred_record",
        "shredded_evidence_id": evidence_id,
        "hash_of_shredded_data": original_hash,
        "shred_timestamp": time.time(),
        "shred_reason": reason,
        "authorized_by": authorized_by,
        "chain_continuity": "hash_preserved_for_chain_verification"
    }

    tombstone = sign_evidence("shred_record", tombstone_data)

    print(f"[shredder] Evidence {evidence_id} shredded")
    print(f"[shredder] Original hash preserved: {original_hash[:32]}...")
    print(f"[shredder] Tombstone record created: {tombstone['evidence_id']}")

    return {
        "status": "shredded",
        "evidence_id": evidence_id,
        "original_hash": original_hash,
        "tombstone_id": tombstone['evidence_id'],
        "reason": reason,
        "authorized_by": authorized_by
    }

def verify_chain_with_shredding() -> list:

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT evidence_id, data, data_hash, prev_hash, signature, public_key, shred_status
        FROM evidence ORDER BY id ASC
    """)
    rows = c.fetchall()
    conn.close()

    import oqs
    results = []
    prev_hash = "GENESIS"

    for row in rows:
        ev_id, data_str, data_hash, stored_prev, signature, pub_key, shred_status = row

        if shred_status == 'shredded':

            chain_ok = stored_prev == prev_hash
            results.append({
                "evidence_id": ev_id,
                "status": "shredded",
                "chain_ok": chain_ok,
                "note": "Data destroyed, hash preserved for chain continuity"
            })
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

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT evidence_id FROM evidence WHERE shred_status = 'active' LIMIT 1")
    row = c.fetchone()
    conn.close()

    if not row:
        print("[shredder] No active evidence found")
        exit()

    target_id = row[0]
    print(f"[shredder] Shredding evidence: {target_id}")
    result = shred_evidence(target_id, reason="retention_expired", authorized_by="admin")
    print(json.dumps(result, indent=2))

    print("\n[shredder] Verifying chain after shredding...")
    results = verify_chain_with_shredding()
    total = len(results)
    valid = sum(1 for r in results if r.get('status') == 'valid')
    shredded = sum(1 for r in results if r.get('status') == 'shredded')
    tampered = sum(1 for r in results if r.get('status') == 'TAMPERED')
    print(f"Total: {total} | Valid: {valid} | Shredded: {shredded} | Tampered: {tampered}")
    print("Chain integrity after shredding: " + ("OK" if tampered == 0 else "VIOLATED"))

