import subprocess
import os
import json
from kubernetes import client, config
from datetime import datetime

#our constants
SCANED_IMAGES = set()
FINDINGS = []
IMAGE_REPORT_FILE_PATH = "image_vulnerability_report.json"
NETWORK_REPORT_FILE_PATH = "network_policy_report.json"
POD_REPORT_FILE_PATH = "pod_security_report.json"
KUBE_BENCH_REPORT_FILE_PATH = "infrastructure_report.json"

'''
This function performs vulnerability scan of container image using trivy and :
    - saves the results in a json file
    - checks if the image has already been scanned to avoid redundant scans.
'''
def image_vulnerability_scan(image_tag):

    # Check if the image has already been scanned and skip if it has
    if image_tag in SCANED_IMAGES:
        print(f"Image {image_tag} already scanned, skipping...")
        return

    print(f"Scanning image: {image_tag}")

    # Run trivy scan and capture output
    try:
        #running trivy scan with specified severity levels and output format
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
        
        # Append new scan entry to reports
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


'''
This function audits RBAC settings for a given pod and container. 
    - It checks for wildcard permissions, secrets access, and pod deletion rights.
    - It returns a list of violations found during the audit.
'''
def rbac_audit(pod, current_container, namespace="free5gc"):
    
    #creating list to store violations found during RBAC audit
    violations = []

    try:
        #initializing Kubernetes client and fetching role bindings and cluster role bindings in the specified namespace
        try:
            config.load_kube_config(config_file="~/.kube/config")
        except Exception:
            print("Config wasn't found")
        rbac_v1 = client.RbacAuthorizationV1Api()
        role_bindings = rbac_v1.list_namespaced_role_binding(namespace)
        cluster_bindings = rbac_v1.list_cluster_role_binding()

        #getting service account name used by the pod
        sa_name = pod.spec.service_account_name

        #creating list to store matched roles and cluster roles for the service account
        matches = []

        #iterating through role bindings
        for rb in role_bindings.items:
            #checking if the role binding has subjects
            if rb.subjects:
                #iterating through subjects of the role binding
                for subject in rb.subjects:
                    #checking if the subject is a service account and if its name matches the service account used by the pod
                    if subject.kind == "ServiceAccount" and subject.name == sa_name:
                        matches.append(("ROLE", rb.role_ref.name))
        
        #iterating through cluster role bindings
        for crb in cluster_bindings.items:
            #checking if the cluster role binding has subjects
            if crb.subjects:
                #iterating through subjects of the cluster role binding
                for subject in crb.subjects:
                    #checking if the subject is a service account and if its name matches the service account used by the pod
                    if subject.kind == "ServiceAccount" and subject.name == sa_name:
                        matches.append(("CLUSTERROLE", crb.role_ref.name))

        #iterating through matched roles and cluster roles to check their permissions
        for role_type, role_name in matches:

            #creating list to store rules associated with the role or cluster role
            rules = []

            #fetching the role or cluster role object based on the role type and extracting its rules
            if role_type == "ROLE":
                role_obj = rbac_v1.read_namespaced_role(role_name, namespace)
                rules = role_obj.rules
            else:
                role_obj = rbac_v1.read_cluster_role(role_name)
                rules = role_obj.rules

            #iterating through rules to check for wildcard permissions, secrets access, and pod deletion rights
            for rule in rules:

                #checking for wildcard permissions
                if "*" in rule.verbs:
                    violation = {
                        "container": current_container.name if pod.spec.containers else "unknown",
                        "issue": f"{role_type} '{role_name}' has wildcard permissions",
                        "severity": "CRITICAL"
                    }
                    violations.append(violation)
                    print(f"[!] {pod.metadata.name} ~ {role_type} {role_name} has wildcard permissions")

                #checking for secrets access
                if "secrets" in (rule.resources or []) and ("get" in rule.verbs or "list" in rule.verbs):
                    violation = {
                        "container": current_container.name if pod.spec.containers else "unknown",
                        "issue": f"{role_type} '{role_name}' can read secrets",
                        "severity": "CRITICAL"
                    }
                    violations.append(violation)
                    print(f"[!] {pod.metadata.name} ~ {role_type} {role_name} can read secrets")
                
                #checking for pod deletion rights
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

'''
This function performs a security audit of pods in the specified namespace.
    - It checks for various security issues such as privileged containers, running as root, writable filesystems, and risky host path mounts.
    - It also calls the RBAC audit function to check for permissions issues 
    - It performs vulnerability scans of container images using the image_vulnerability_scan function.
    - The results of the audit are saved in a JSON report file.
'''
def audit_pod_security(namespace="free5gc"):
    #loading Kubernetes configuration and initializing API client to list pods in the specified namespace
    try:
        config.load_kube_config(config_file="~/.kube/config")
    except Exception:
        print("Config wasn't found")
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    
    #iterating through pods and their containers to perform security checks and audits
    for pod in pods.items:
        
        #creating a report structure for the current pod to store metadata and violations found during the audit
        pod_raport = {
            "pod_name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "labels": pod.metadata.labels or {},
            "timestamp": datetime.now().isoformat(),
            "violations": []
        }

        #iterating through containers in the pod
        for container in pod.spec.containers:

            #getting security context of the container
            securityContext = container.security_context
            print(f"\n----- Auditing Pod: {pod.metadata.name} | Container: {container.name} -----")
            
            #checking if security context is defined for the container
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
                #checking if pod is running as root user
                if securityContext.run_as_user==0 and not securityContext.run_as_non_root:
                    print(f"[!] Running as root")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Running as root",
                        "severity": "CRITICAL"
                    })
                #checking if privilege escalation is allowed
                if securityContext.allow_privilege_escalation:
                    print(f"[!] Privilege escalation allowed")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Privilege escalation allowed",
                        "severity": "HIGH"
                    })

                #file system access
                #checking if root filesystem is writable
                if not securityContext.read_only_root_filesystem:
                    print(f"[!] Writable root filesystem")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Writable root filesystem",
                        "severity": "HIGH"
                    })
                #checking if seccomp profile is set
                if not securityContext.seccomp_profile:
                    print(f"[!] Seccomp is not set")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Seccomp is not set",
                        "severity": "MEDIUM"
                    })
                
                #resource access
                #list of risky host paths that should not be mounted in containers
                risky_mounts = ["/", "/etc", "/root", "/var/run/docker.sock", "/var/log"]

                #checking if resource limits are set for the container
                if not container.resources.limits:
                    print(f"[!] No resource limits")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "No resource limits",
                        "severity": "MEDIUM"
                    })
                else:
                    #checking if cpu limit is set for the container
                    if not container.resources.limits.get("cpu"):
                        print(f"[!] No cpu limit")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": "No cpu limit",
                            "severity": "MEDIUM"
                        })
                    #checking if memory limit is set for the container
                    if not container.resources.limits.get("memory"):
                        print(f"[!] No memory limit")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": "No memory limit",
                            "severity": "MEDIUM"
                        })

                #checking for risky host path mounts in the container's volume mounts
                for volume in pod.spec.volumes:
                    if volume.host_path and volume.host_path.path in risky_mounts:
                        print(f"[!] ~ risky host path mount: {volume.host_path.path}")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": f"Risky host path mount: {volume.host_path.path}",
                            "severity": "HIGH"
                        })
                
                #capabilities
                #getting capabilities from the security context of the container
                caps = securityContext.capabilities

                #checking if capabilities are set and if they are not dropped by default
                if caps is None:
                    print(f"[!] Capabilities are not set and are not dropped by default")
                    pod_raport["violations"].append({
                        "container": container.name,
                        "issue": "Capabilities are not set and are not dropped by default",
                        "severity": "HIGH"
                    })
                else:
                    #checking if all capabilities are dropped for the container
                    if caps.drop is None or "ALL" not in caps.drop:
                        print(f"[!] Capabilities are not fully dropped")
                        pod_raport["violations"].append({
                            "container": container.name,
                            "issue": "Capabilities are not fully dropped",
                            "severity": "HIGH"
                        })

                #manualy typed secrets
                #checking environment variables for potential secrets by looking for keywords in their values
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
                #performing RBAC audit for the current pod and container and appending any violations found to the pod report
                rbac_violations = rbac_audit(pod, container, namespace)
                pod_raport["violations"].extend(rbac_violations)
                
                #container image scan
                #performing vulnerability scan of the container image using the image_vulnerability_scan function
                image_vulnerability_scan(container.image)
        
        # saving pod raport
        try:
            #check if pod raport file exists and load existing reports, otherwise create new structure
            if os.path.exists(POD_REPORT_FILE_PATH):
                with open(POD_REPORT_FILE_PATH, "r") as f:
                    pod_reports = json.load(f)
            else:
                pod_reports = {"pods": []}

            #append current pod report to the list of pod reports and write back to file
            pod_reports["pods"].append(pod_raport)

            #write updated pod reports back to the JSON file
            with open(POD_REPORT_FILE_PATH, "w") as f:
                json.dump(pod_reports, f, indent=2)
        except Exception as e:
            print(f"Error writing pod report: {e}")
            

'''
this function performs a security audit of the Kubernetes infrastructure using kube-bench tool.
    - It runs kube-bench with specified parameters to check for compliance with CIS Kubernetes Benchmark.
    - It parses the results to identify any failed or warning checks and compiles a report of violations found during the audit.
    - The results are saved in a JSON report file for further analysis and hardening measures.
'''
def kube_bench():
    try:
        #running kube-bench with specified parameters to perform security audit of the Kubernetes infrastructure
        output = subprocess.run(["sudo", "kube-bench", "run", "--targets", "node", "--benchmark", "cis-1.24-microk8s", "--config-dir", "cfg", "--json"], capture_output=True, text=True)
        results = json.loads(output.stdout)
        
        # Create infrastructure report
        infrastructure_report = {
            "timestamp": datetime.now().isoformat(),
            "benchmark": "cis-1.24-microk8s",
            "target": "node",
            "violations": []
        }
        
        #parsing kube-bench results to identify any failed or warning checks and compiling a report of violations found during the audit
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
            #check if infrastructure report file exists and load existing reports, otherwise create new structure
            if os.path.exists(KUBE_BENCH_REPORT_FILE_PATH):
                with open(KUBE_BENCH_REPORT_FILE_PATH, "r") as f:
                    report_data = json.load(f)
            else:
                report_data = {"infrastructure_audits": []}

            #append current infrastructure report to the list of infrastructure audits and write back to file
            report_data["infrastructure_audits"].append(infrastructure_report)

            #write updated infrastructure audits back to the JSON file
            with open(KUBE_BENCH_REPORT_FILE_PATH, "w") as f:
                json.dump(report_data, f, indent=2)
            
            print(f"Kube-bench results saved to {KUBE_BENCH_REPORT_FILE_PATH}")
        except Exception as e:
            print(f"Error writing infrastructure report: {e}")
            
    except subprocess.CalledProcessError as e:
        print(f"Error running kube-bench: {e.stderr}")
    except json.JSONDecodeError as e:
        print(f"Error parsing kube-bench output: {e}")

'''
This function performs an audit of network policies in the specified namespace.
    - It checks for the presence of network policies and identifies any violations such as lack of policies
    - The results of the audit are saved in a JSON report file for further analysis and hardening measures.
'''
def network_policy_audit(namespace="free5gc"):
    #loading Kubernetes configuration and initializing API client to list network policies in the specified namespace
    try:
        config.load_kube_config(config_file="~/.kube/config")
    except Exception:
        print("Config wasn't found")
    networking1v = client.NetworkingV1Api()
    policies = networking1v.list_namespaced_network_policy(namespace)

    print(f"\n----- Auditing network policies -----")

    #creating a report structure for network policies to store metadata and violations found during the audit
    network_policy_report = {
        "namespace": namespace,
        "timestamp": datetime.now().isoformat(),
        "violations": []
    }

    #checking if any network policies are found in the specified namespace and adding a violation to the report if none are found
    if not policies.items:
        print("[!] No network policies found.")
        network_policy_report["violations"].append({
            "issue": "No network policies found",
            "severity": "CRITICAL"
        })

    # saving network policy report
    try:
        #check if network policy report file exists and load existing reports, otherwise create new structure
        if os.path.exists(NETWORK_REPORT_FILE_PATH):
            with open(NETWORK_REPORT_FILE_PATH, "r") as f:
                report_data = json.load(f)
        else:
            report_data = {"network_policies": []}

        #append current network policy report to the list of network policies and write back to file
        report_data["network_policies"].append(network_policy_report)

        #write updated network policies back to the JSON file
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