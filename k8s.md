# Kubernetes Security and Compliance Checklist
This checklist ensures best practices for Kubernetes security and compliance across different resources.

## 1. Infrastructure Security
### kubernetes_service
 HIGH - Ensure that the --secure-port argument is not set to 0.
 MEDIUM - Ensure that the Tiller Service (Helm v2) is not deployed for Kubernetes service.
 MEDIUM - Ensure the use of externalIPs is restricted for Kubernetes service.
 LOW - Ensure for exposing Kubernetes workload to the internet, NodePort service is not used.
 LOW - Ensure the use of selector is enforced for Kubernetes Ingress or LoadBalancer service.
### kubernetes_pod
 HIGH - Ensure that the --insecure-bind-address argument is not set.
 HIGH - Ensure that the --insecure-port argument is set to 0.
 HIGH - Ensure that the --secure-port argument is not set to 0.
 HIGH - Prefer using secrets as files over secrets as environment variables.
 MEDIUM - Ensure that the --kubelet-certificate-authority argument is set as appropriate.
 MEDIUM - Ensure that the --bind-address argument is set to 127.0.0.1.
 MEDIUM - Ensure that the --client-cert-auth argument is set to true.
 MEDIUM - Ensure that the API Server only makes use of strong cryptographic ciphers.
### kubernetes_network_policies
 HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to query DNS.
 HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to SSH.
 HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to access SQL servers.
 HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to access Redis servers.
 MEDIUM - Ensure Kubernetes Network policy attached to a pod has Ingress/Egress blocks specified.
### kubernetes_ingress_nginx
 HIGH - Ensure metadata annotations are restricted in an Ingress object.
### kubernetes_ingress
 MEDIUM - Ensure HTTPS is enabled on Kubernetes Ingress resource.
