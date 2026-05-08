import subprocess
import os
import json
from kubernetes import client, config
from datetime import datetime

SCANED_IMAGES = set()
FINDINGS = []
IMAGE_REPORT_FILE_PATH = "image_vulnerability_report.json"
NETWORK_REPORT_FILE_PATH = "network_policy_report.json"
POD_REPORT_FILE_PATH = "pod_security_report.json"
KUBE_BENCH_REPORT_FILE_PATH = "infrastructure_report.json"

def image_vulnerability_scan(image_tag):

    if image_tag in SCANED_IMAGES:
        print(f"Image {image_tag} already scanned, skipping...")
        return

    print(f"Scanning image: {image_tag}")
    try:
        output = subprocess.run(["trivy", "image", "--severity", "HIGH,CRITICAL", "-q", image_tag, "--format", "json"], capture_output=True, text=True)
        # Load existing reports or create new structure
        if os.path.exists(IMAGE_REPORT_FILE_PATH):
            with open(IMAGE_REPORT_FILE_PATH, "r") as f:
                reports = json.load(f)
        else:
            reports = {"scans": []}
        
        # Parse trivy output
        trivy_results = json.loads(output.stdout) if output.stdout.strip() else {}
        
        # Create scan entry with metadata
        scan_entry = {
            "image": image_tag,
            "results": trivy_results
        }
        
        reports["scans"].append(scan_entry)
        
        # Write back to file
        with open(IMAGE_REPORT_FILE_PATH, "w") as report_file:
            json.dump(reports, report_file, indent=2)
        
        print(f"Scan results for {image_tag} written to {IMAGE_REPORT_FILE_PATH}")
    except json.JSONDecodeError as e:
        print(f"Error parsing trivy output for {image_tag}: {e}")
    except subprocess.CalledProcessError as e:
        print(f"Error scanning image {image_tag}: {e.stderr}")
    except Exception as e:
        print(f"Error writing scan results: {e}")
    
    SCANED_IMAGES.add(image_tag)

def rbac_audit(pod, current_container, namespace="free5gc"):
    violations = []
    try:
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
            rules = []
            if role_type == "ROLE":
                role_obj = rbac_v1.read_namespaced_role(role_name, namespace)
                rules = role_obj.rules
            else:
                role_obj = rbac_v1.read_cluster_role(role_name)
                rules = role_obj.rules

            for rule in rules:
                if "*" in rule.verbs:
                    violation = {
                        "container": current_container.name if pod.spec.containers else "unknown",
                        "issue": f"{role_type} '{role_name}' has wildcard permissions",
                        "severity": "CRITICAL"
                    }
                    violations.append(violation)
                    print(f"[!] {pod.metadata.name} ~ {role_type} {role_name} has wildcard permissions")

                if "secrets" in (rule.resources or []) and ("get" in rule.verbs or "list" in rule.verbs):
                    violation = {
                        "container": current_container.name if pod.spec.containers else "unknown",
                        "issue": f"{role_type} '{role_name}' can read secrets",
                        "severity": "CRITICAL"
                    }
                    violations.append(violation)
                    print(f"[!] {pod.metadata.name} ~ {role_type} {role_name} can read secrets")
                
                if "pods" in (rule.resources or []) and "delete" in rule.verbs:
                    violation = {
                        "container": current_container.name if pod.spec.containers else "unknown",
                        "issue": f"{role_type} '{role_name}' can delete pods",
                        "severity": "HIGH"
                    }
                    violations.append(violation)
                    print(f"[!] {pod.metadata.name} ~ {role_type} {role_name} can delete pods")
    except Exception as e:
        print(f"Error during RBAC audit: {e}")
    
    return violations
        

def audit_pod_security(namespace="free5gc"):
    try:
        config.load_kube_config(config_file="~/.kube/config")
    except Exception:
        print("Config wasn't found")
        
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    
    for pod in pods.items:
        
        pod_raport = {
            "pod_name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "labels": pod.metadata.labels or {},
            "timestamp": datetime.now().isoformat(),
            "violations": []
        }

        for container in pod.spec.containers:
            securityContext = container.security_context
            print(f"\n----- Auditing Pod: {pod.metadata.name} | Container: {container.name} -----")
            
            if not securityContext:
                print(f"[!] no security context")
                pod_raport["violations"].append({
                    "container": container.name,
                    "issue": "No security context defined",
                    "severity": "CRITICAL"
                })
            else:
                #checking if pod has root access
                if securityContext.privileged:
                    print(f"[!] Privleged: True")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Privileged container",
                        "severity": "CRITICAL"
                    })
                if securityContext.run_as_user==0 and not securityContext.run_as_non_root:
                    print(f"[!] Running as root")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Running as root",
                        "severity": "CRITICAL"
                    })
                if securityContext.allow_privilege_escalation:
                    print(f"[!] Privilege escalation allowed")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Privilege escalation allowed",
                        "severity": "HIGH"
                    })

                #flie system access
                if not securityContext.read_only_root_filesystem:
                    print(f"[!] Writable root filesystem")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Writable root filesystem",
                        "severity": "HIGH"
                    })
                if not securityContext.seccomp_profile:
                    print(f"[!] Seccomp is not set")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Seccomp is not set",
                        "severity": "MEDIUM"
                    })
                
                #recource access
                risky_mounts = ["/", "/etc", "/root", "/var/run/docker.sock", "/var/log"]

                if not container.resources.limits:
                    print(f"[!] No resource limits")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "No resource limits",
                        "severity": "MEDIUM"
                    })
                else:
                    if not container.resources.limits.get("cpu"):
                        print(f"[!] No cpu limit")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": "No cpu limit",
                            "severity": "MEDIUM"
                        })
                    if not container.resources.limits.get("memory"):
                        print(f"[!] No memory limit")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": "No memory limit",
                            "severity": "MEDIUM"
                        })

                for volume in pod.spec.volumes:
                    if volume.host_path and volume.host_path.path in risky_mounts:
                        print(f"[!] ~ risky host path mount: {volume.host_path.path}")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": f"Risky host path mount: {volume.host_path.path}",
                            "severity": "HIGH"
                        })
                
                #capabilities
                caps = securityContext.capabilities
                if caps is None:
                    print(f"[!] Capabilities are not set and are not dropped by default")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Capabilities are not set and are not dropped by default",
                        "severity": "HIGH"
                    })
                else:
                    if caps.drop is None or "ALL" not in caps.drop:
                        print(f"[!] Capabilities are not fully dropped")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": "Capabilities are not fully dropped",
                            "severity": "HIGH"
                        })

                #manualy typed secrets
                if container.env:
                    for env in container.env:
                        if env.value:
                            if any(secret_words in env.value.upper() for secret_words in ["PASS", "TOKEN", "KEY", "SECRET", "PASSWORD"]):
                                print(f"[!] environment variable {env.name} may contain sensitive information")
                                pod_raport["violations"].append({
                                    "container": container.name,
                                    "issue": f"Environment variable '{env.name}' may contain sensitive information",
                                    "severity": "CRITICAL"
                                })

                #rbac
                rbac_violations = rbac_audit(pod, container, namespace)
                pod_raport["violations"].extend(rbac_violations)
                
                #conteiner image scan
                image_vulnerability_scan(container.image)
        
        # saving pod raport
        try:
            if os.path.exists(POD_REPORT_FILE_PATH):
                with open(POD_REPORT_FILE_PATH, "r") as f:
                    pod_reports = json.load(f)
            else:
                pod_reports = {"pods": []}

            pod_reports["pods"].append(pod_raport)

            with open(POD_REPORT_FILE_PATH, "w") as f:
                json.dump(pod_reports, f, indent=2)
        except Exception as e:
            print(f"Error writing pod report: {e}")
            

def kube_bench():
    try:
        output = subprocess.run(["sudo", "kube-bench", "run", "--targets", "node", "--benchmark", "cis-1.24-microk8s", "--config-dir", "cfg", "--json"], capture_output=True, text=True)
        results = json.loads(output.stdout)
        
        # Create infrastructure report
        infrastructure_report = {
            "timestamp": datetime.now().isoformat(),
            "benchmark": "cis-1.24-microk8s",
            "target": "node",
            "violations": []
        }
        
        for section in results.get("Controls", []):
            for test in section.get("tests", []):
                for result in test.get("results", []):
                    if result.get("status") == "FAIL" or result.get("status") == "WARN":
                        violation = {
                            "test_number": result.get("test_number"),
                            "description": result.get("test_desc"),
                            "status": result.get("status"),
                            "remediation": result.get("remediation"),
                            "actual_value": result.get("actual_value", ""),
                            "severity": "CRITICAL" if result.get("status") == "FAIL" else "WARNING"
                        }
                        infrastructure_report["violations"].append(violation)
                        #print(f"test number: {result.get('test_number')}\nDescription: {result.get('test_desc')}\nStatus: {result.get('status')}\nFIX: {result.get('remediation')}\n")
        
        # Save infrastructure report
        try:
            if os.path.exists(KUBE_BENCH_REPORT_FILE_PATH):
                with open(KUBE_BENCH_REPORT_FILE_PATH, "r") as f:
                    report_data = json.load(f)
            else:
                report_data = {"infrastructure_audits": []}

            report_data["infrastructure_audits"].append(infrastructure_report)

            with open(KUBE_BENCH_REPORT_FILE_PATH, "w") as f:
                json.dump(report_data, f, indent=2)
            
            print(f"Kube-bench results saved to {KUBE_BENCH_REPORT_FILE_PATH}")
        except Exception as e:
            print(f"Error writing infrastructure report: {e}")
            
    except subprocess.CalledProcessError as e:
        print(f"Error running kube-bench: {e.stderr}")
    except json.JSONDecodeError as e:
        print(f"Error parsing kube-bench output: {e}")

def network_policy_audit(namespace="free5gc"):
    config.load_kube_config(config_file="~/.kube/config")

    networking1v = client.NetworkingV1Api()
    policies = networking1v.list_namespaced_network_policy(namespace)

    print(f"\n----- Auditing network policies -----")

    network_policy_report = {
        "namespace": namespace,
        "timestamp": datetime.now().isoformat(),
        "violations": []
    }

    if not policies.items:
        print("[!] No network policies found.")
        network_policy_report["violations"].append({
            "issue": "No network policies found",
            "severity": "CRITICAL"
        })

    # saving network policy report
    try:
        if os.path.exists(NETWORK_REPORT_FILE_PATH):
            with open(NETWORK_REPORT_FILE_PATH, "r") as f:
                report_data = json.load(f)
        else:
            report_data = {"network_policies": []}

        report_data["network_policies"].append(network_policy_report)

        with open(NETWORK_REPORT_FILE_PATH, "w") as f:
            json.dump(report_data, f, indent=2)
    except Exception as e:
        print(f"Error writing network policy report: {e}")

#main
if __name__ == "__main__":
    #cleaning up the file before writing new report
    try:
        #check if image raport file exists and remove it
        if os.path.exists(IMAGE_REPORT_FILE_PATH):
            os.remove(IMAGE_REPORT_FILE_PATH)
        
        #check if pod raport file exists and remove it
        if os.path.exists(POD_REPORT_FILE_PATH):
            os.remove(POD_REPORT_FILE_PATH)
        
        #check if network raport file exists and remove it
        if os.path.exists(NETWORK_REPORT_FILE_PATH):
            os.remove(NETWORK_REPORT_FILE_PATH)
        
        #check if infrastructure report file exists and remove it
        if os.path.exists(KUBE_BENCH_REPORT_FILE_PATH):
            os.remove(KUBE_BENCH_REPORT_FILE_PATH)

    except Exception as e:
        print(f"Error cleaning up report file: {e}")
    
    
    #audits
    kube_bench()
    audit_pod_security()
    network_policy_audit()