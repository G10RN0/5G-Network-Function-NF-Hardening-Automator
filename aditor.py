import subprocess
import os
import json
from kubernetes import client, config

def image_vulnerability_scan(image_tag):
    print(f"Scanning image: {image_tag}")
    output = subprocess.run(["trivy", "image", "--severity", "HIGH,CRITICAL", "-q", image_tag], capture_output=True, text=True)
    with open("image_vulnerability_report.txt", "a") as report_file:
        report_file.write(f"Vulnerability scan for image: {image_tag}\n")
        report_file.write(output.stdout)
        report_file.write("\n")
    print("output written to image_vulnerability_report.txt")

def rbac_audit(pod, namespace="free5gc"):
    config.load_kube_config(config_file="~/.kube/config")
    rbac_v1 = client.RbacAuthorizationV1Api()
    role_bindings = rbac_v1.list_namespaced_role_binding(namespace)
    cluster_bindings = rbac_v1.list_cluster_role_binding()

    sa_name = pod.spec.service_account_name

    matches = []

    for rb in role_bindings.items:
        if rb.subjects:
            for subject in rb.subjects:
                if subject.kind == "ServiceAccount" and subject.name == sa_name:
                    matches.append(("ROLE", rb.role_ref.name))
    
    for crb in cluster_bindings.items:
        if crb.subjects:
            for subject in crb.subjects:
                if subject.kind == "ServiceAccount" and subject.name == sa_name:
                    matches.append(("CLUSTERROLE", crb.role_ref.name))

    for role_type, role_name in matches:
        rules=[]
        if role_type =="ROLE":
            role_obj = rbac_v1.read_namespaced_role(role_name, namespace)
            rules = role_obj.rules
        else:
            role_obj = rbac_v1.read_cluster_role(role_name)
            rules = role_obj.rules

        for rule in rules:
            if "*" in rule.verbs:
                print(f"{pod.metadata.name} ~ {role_type} {role_name} has wildcard permissions")

            if "secrets" in (rule.resources or []) and ("get" in rule.verbs or "list" in rule.verbs):
                print(f"{pod.metadata.name} ~ {role_type} {role_name} can read secrets")
            
            if "pods" in (rule.resources or []) and "delete" in rule.verbs:
                print(f"{pod.metadata.name} ~ {role_type} {role_name} can delete pods")
            print("im here")
        

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
            if securityContext.run_as_user==0 and not securityContext.run_as_non_root:
                print(f"{container.name} ~ run as root")
            if securityContext.allow_privilege_escalation:
                print(f"{container.name} ~ allow privileged escaletion")

            #flie system access
            if not securityContext.read_only_root_filesystem:
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

            #manualy typed secrets
            if container.env:
                for env in container.env:
                    if any(secret_words in env.value.upper() for secret_words in ["PASS", "TOKEN", "KEY", "SECRET", "PASSWORD"]):
                        print(f"{container.name} ~ environment variable {env.name} may contain sensitive information")
            
            #rbac
            rbac_audit(pod, namespace)
            
            #conteiner image scan
            image_vulnerability_scan(container.image)
            print()

def kube_bench():
    try:
        output = subprocess.run(["sudo", "kube-bench", "run", "--targets", "node", "--benchmark", "cis-1.24-microk8s", "--config-dir", "cfg", "--json"], capture_output=True, text=True)
        results = json.loads(output.stdout)
        for section in results.get("Controls", []):
            for test in section.get("tests", []):
                for result in test.get("results", []):
                    if result.get("status") == "FAIL" or result.get("status") == "WARN":
                        print(f"test number: {result.get('test_number')}\nDescription: {result.get('test_desc')}\nFIX: {result.get('remediation')}")
    except subprocess.CalledProcessError as e:
        print(f"Error running kube-bench: {e.stderr}")
    except json.JSONDecodeError as e:
        print(f"Error parsing kube-bench output: {e}")

def network_policy_audit(namespace="free5gc"):
    config.load_kube_config(config_file="~/.kube/config")
    networking1v = client.NetworkingV1Api()
    policies = networking1v.list_namespaced_network_policy(namespace)
    if not policies.items:
        print("No network policies found.")    

if __name__ == "__main__":
    kube_bench()
    audit_pod_security()
    network_policy_audit()