import os
from kubernetes import client, config

def audit_pod_security(namespace="free5gc"):
    try:
        config.load_kube_config(config_file="~/.kube/config")
    except Exception:
        print("Config wasn't found")
        
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    
    for pod in pods.items:
        container = pod.spec.containers[0]
        # CHECK 1: Is it running as root?
        run_as_non_root = container.security_context.run_as_non_root
        # CHECK 2: Is the filesystem writable?
        read_only_fs = container.security_context.read_only_root_filesystem
        
        print(f"Pod: {pod.metadata.name} | Non-Root: {run_as_non_root} | RO-FS: {read_only_fs}")
        
audit_pod_security()