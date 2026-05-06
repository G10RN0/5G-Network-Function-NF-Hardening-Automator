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
        securityContext = container.security_context
        if securityContext is None:
            print("critical: securityContext should be defined ")
        else:
            if securityContext.privileged:
                print("critical")
            if securityContext.run_as_user==0 and not securityContext.run_as_none_root:
                print("high")
            caps = securityContext.capabilities
            print(caps)
        
audit_pod_security()