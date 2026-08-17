import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from kubernetes import client, config
from crypto_core import sign_evidence, init_db, generate_or_load_keypair
import json
import time

def load_k8s_config():
    try:
        config.load_incluster_config()
        print("[collector] Running inside cluster")
    except:
        config.load_kube_config()
        print("[collector] Running outside cluster (local kubeconfig)")

def collect_pods(namespace="default") -> list:
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace)
    collected = []
    for pod in pods.items:
        pod_data = {
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "status": pod.status.phase,
            "node": pod.spec.node_name,
            "image_digests": [
                c.image_id for c in (pod.status.container_statuses or [])
            ],
            "labels": pod.metadata.labels or {},
            "creation_timestamp": str(pod.metadata.creation_timestamp),
        }
        result = sign_evidence("pod_metadata", pod_data)
        print(f"[collector] Pod '{pod.metadata.name}' signed: {result['evidence_id']}")
        collected.append(result)
    return collected

def collect_events(namespace="default") -> list:
    v1 = client.CoreV1Api()
    events = v1.list_namespaced_event(namespace=namespace)
    collected = []
    for event in events.items:
        event_data = {
            "name": event.metadata.name,
            "namespace": event.metadata.namespace,
            "reason": event.reason,
            "message": event.message,
            "type": event.type,
            "involved_object": event.involved_object.name,
            "first_timestamp": str(event.first_timestamp),
            "last_timestamp": str(event.last_timestamp),
            "count": event.count,
        }
        result = sign_evidence("k8s_event", event_data)
        print(f"[collector] Event '{event.reason}' signed: {result['evidence_id']}")
        collected.append(result)
    return collected

def collect_pod_logs(namespace="default") -> list:
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace)
    collected = []
    for pod in pods.items:
        if pod.status.phase != "Running":
            continue
        try:
            logs = v1.read_namespaced_pod_log(
                name=pod.metadata.name,
                namespace=namespace,
                tail_lines=50
            )
            log_data = {
                "pod_name": pod.metadata.name,
                "namespace": namespace,
                "logs": logs[:2000],
            }
            result = sign_evidence("pod_logs", log_data)
            print(f"[collector] Logs of '{pod.metadata.name}' signed: {result['evidence_id']}")
            collected.append(result)
        except Exception as e:
            print(f"[collector] Could not get logs for {pod.metadata.name}: {e}")
    return collected

def run_collection_cycle(namespace="default"):
    print(f"\n[collector] === Collection cycle started: {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    pods = collect_pods(namespace)
    events = collect_events(namespace)
    logs = collect_pod_logs(namespace)
    total = len(pods) + len(events) + len(logs)
    print(f"[collector] === Cycle complete: {total} artifacts signed ===\n")
    return total

def run_agent(namespace="default", interval=30):
    init_db()
    generate_or_load_keypair()
    load_k8s_config()
    print(f"[collector] Agent started, collection interval: {interval}s")
    while True:
        try:
            run_collection_cycle(namespace)
        except Exception as e:
            print(f"[collector] Error during collection: {e}")
        time.sleep(interval)

if __name__ == "__main__":
    namespace = os.environ.get("FORENSICS_NAMESPACE", "default")
    interval = int(os.environ.get("FORENSICS_INTERVAL", "30"))
    run_agent(namespace=namespace, interval=interval)
