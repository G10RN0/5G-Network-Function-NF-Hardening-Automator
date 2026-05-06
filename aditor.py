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
        securityContex = container.get('securityContext', {})
        
        if securityContex.get("prevliged"):
            print("critical")
        if securityContex.get("runAsUser")==0 and not securityContex.get("runAsNoneRoot"):
            print("high")
        caps = securityContex.get('capabilities', {})
        print(caps)
        
audit_pod_security()