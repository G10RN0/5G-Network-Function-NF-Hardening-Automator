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
            if securityContext.allow_privilege_escalation:
                print(f"{container.name} ~ allow privileged escaletion")

            #flie system access
            if securityContext.read_only_root_filesystem is False:
                print(f"{container.name} ~ read only root file system is false")
            if securityContext.seccomp_profile == None:
                print(f"{container.name} ~ seccomp is not set")
            
            #recource access
            risky_mounts = ["/", "/etc", "/root", "/var/run/docker.sock", "/var/log"]

            if container.resources.limits == None:
                print(f"{container.name} ~ no resource limits")
            else:
                if container.resources.limits.get("cpu") == None:
                    print(f"{container.name} ~ no cpu limit")
                if container.resources.limits.get("memory") == None:
                    print(f"{container.name} ~ no memory limit")

            for volume in pod.spec.volumes:
                if volume.host_path and volume.host_path.path in risky_mounts:
                    print(f"{container.name} ~ risky host path mount: {volume.host_path.path}")
            
            #capabilities
            caps = securityContext.capabilities
            if caps is None:
                print(f"{container.name} ~ capabilities are not set")
            else:
                if caps.drop is None or "ALL" not in caps.drop:
                    print(f"{container.name} ~ does not drop all capabilities")

if __name__ == "__main__":
    audit_pod_security()