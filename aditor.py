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
        
        print(f"checking conteiner: {container.name}")
        if securityContext is None:
            print(f"{container.name} ~ no security context")
        else:
            #checking if pod has root access
            if securityContext.privileged:
                print(f"{container.name} ~ privileged")
            if securityContext.run_as_user==0 and securityContext.run_as_none_root is False:
                print(f"{container.name} ~ run as root")
            if securityContext.allow_privileg_escalation:
                print(f"{container.name} ~ allow privileged escaletion")
            caps = securityContext.capabilities
            print(caps)

if __name__ == "__main__":
    audit_pod_security()