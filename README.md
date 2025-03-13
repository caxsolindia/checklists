# Kubernetes Security and Compliance Checklist
This checklist ensures best practices for Kubernetes security and compliance across different resources.

## 1. **Infrastructure Security**
### kubernetes_service
 - [ ] HIGH - Ensure that the --secure-port argument is not set to 0.
 - [ ] MEDIUM - Ensure that the Tiller Service (Helm v2) is not deployed for Kubernetes service.
 - [ ] MEDIUM - Ensure the use of externalIPs is restricted for Kubernetes service.
 - [ ] LOW - Ensure for exposing Kubernetes workload to the internet, NodePort service is not used.
 - [ ] LOW - Ensure the use of selector is enforced for Kubernetes Ingress or LoadBalancer service.

### kubernetes_network_policies
 - [ ] HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to query DNS.
 - [ ] HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to SSH.
 - [ ] HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to access SQL servers.
 - [ ] HIGH - Ensure Kubernetes Network policy does not allow ingress from public IPs to access Redis servers.
 - [ ] MEDIUM - Ensure Kubernetes Network policy attached to a pod has Ingress/Egress blocks specified.
### kubernetes_ingress_nginx
 - [ ] HIGH - Ensure metadata annotations are restricted in an Ingress object.
### kubernetes_ingress
 - [ ] MEDIUM - Ensure HTTPS is enabled on Kubernetes Ingress resource.


=======================================================================

### Kubernetes Pod Security
#### High Priority

- [ ] Ensure kernel level call configurations are not vulnerable to CVE-2022-0811 in all Kubernetes workloads.

- [ ] Minimize the admission of privileged containers.

- [ ] Ensure that the admission control plugin SecurityContextDeny is set if PodSecurityPolicy is not used.

- [ ] Ensure that the --insecure-bind-address argument is not set.

- [ ] Ensure that the --insecure-port argument is set to 0.

- [ ] Ensure custom snippets annotations is not set to true for Ingress-nginx controller deployment's Kubernetes Config Map.

- [ ] Ensure mounting of hostPaths is disallowed in Kubernetes workload configuration.

- [ ] Ensure that the --secure-port argument is not set to 0.

- [ ] Minimize the admission of containers with allowPrivilegeEscalation.

- [ ] Minimize the admission of root containers.

- [ ] Prefer using secrets as files over secrets as environment variables.

Medium Priority

- [ ] Ensure kube-controller-manager is not vulnerable to CVE-2020-8555.

- [ ] Ensure that the admission control plugin AlwaysPullImages is set.

- [ ] Ensure that the admission control plugin NodeRestriction is set.

- [ ] Ensure that the --audit-log-maxage argument is set to 30 or as appropriate.

- [ ] Ensure that the --terminated-pod-gc-threshold argument is set as appropriate.

- [ ] Ensure that the --root-ca-file argument is set as appropriate.

- [ ] Ensure that the Tiller Service (Helm v2) is not deployed for Kubernetes workloads.

- [ ] Ensure kernel and system level calls are not configured in all Kubernetes workloads.

- [ ] Ensure 'readOnlyRootFileSystem' is set to true in Kubernetes workload configuration.

- [ ] Ensure that the --basic-auth-file argument is not set.

- [ ] Ensure that the --kubelet-certificate-authority argument is set as appropriate.

- [ ] Ensure that the --service-account-key-file argument is set as appropriate.

- [ ] Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate.

- [ ] Ensure that the --etcd-cafile argument is set as appropriate.

- [ ] Ensure that the admission control plugin AlwaysAdmit is not set.

- [ ] Ensure that the --bind-address argument is set to 127.0.0.1.

- [ ] Ensure that the --cert-file and --key-file arguments are set as appropriate.

- [ ] Minimize the admission of containers with the NET_RAW capability.

- [ ] Ensure CPU request is set for Kubernetes workloads.

- [ ] Ensure that the admission control plugin PodSecurityPolicy is set.

- [ ] Minimize the admission of containers wishing to share the host network namespace.

- [ ] Ensure that the admission control plugin NamespaceLifecycle is set.

- [ ] Ensure that the --request-timeout argument is set as appropriate.

- [ ] Ensure that the --service-account-private-key-file argument is set as appropriate.

- [ ] Ensure that a unique Certificate Authority is used for etcd.

- [ ] Ensure that the --token-auth-file parameter is not set.

- [ ] Ensure that the --kubelet-https argument is set to true.

- [ ] Ensure that the --authorization-mode argument includes Node.

- [ ] Ensure that the --profiling argument is set to false.

- [ ] Ensure that Service Account Tokens are only mounted where necessary.

- [ ] Ensure that a minimal audit policy is created.

- [ ] Ensure that the seccomp profile is set to docker/default in pod definitions.

- [ ] Minimize the admission of containers wishing to share the host IPC namespace.

- [ ] Ensure that Anonymous Auth is not enabled.

- [ ] Minimize the admission of containers with added capabilities.

- [ ] Ensure that the --audit-log-path argument is set.

- [ ] Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate.

- [ ] Ensure that the API Server only makes use of strong cryptographic ciphers.

- [ ] Ensure that the --client-cert-auth argument is set to true.

- [ ] Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate.

- [ ] Ensure that every container image has a hash digest in all Kubernetes workloads.

- [ ] Ensure AppArmor profile is not set to runtime/default in Kubernetes workload configuration.

- [ ] Ensure 'procMount' is set to default in all Kubernetes workloads.

- [ ] Ensure containers run with a high UID (usually > 1000) to avoid host conflict.

- [ ] Ensure only allowed volume types are mounted for all Kubernetes workloads.

- [ ] Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate.

- [ ] Ensure Memory request is set for Kubernetes workloads.

- [ ] Ensure that the RotateKubeletServerCertificate argument is set to true.

- [ ] Apply Security Context to Your Pods and Containers.

- [ ] Ensure that the --authorization-mode argument includes RBAC.

- [ ] Ensure that the admission control plugin EventRateLimit is set.

- [ ] Ensure that the admission control plugin ServiceAccount is set.

- [ ] Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate.

- [ ] Ensure that the --service-account-lookup argument is set to true.

- [ ] Ensure that the --encryption-provider-config argument is set as appropriate.

- [ ] Ensure that the --auto-tls argument is not set to true.

- [ ] Ensure that the --peer-client-cert-auth argument is set to true.

- [ ] Ensure that the --peer-auto-tls argument is not set to true.

- [ ] Ensure Kubernetes dashboard is not deployed.

- [ ] Ensure mounting Docker socket daemon in a container is limited.

- [ ] Ensure CPU limit is set for Kubernetes workloads.

- [ ] Ensure security context is applied to pods and containers with SELinux configured.

- [ ] Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate.

- [ ] Ensure that a Client CA File is Configured.

- [ ] Minimize the admission of containers wishing to share the host process ID namespace.

- [ ] Ensure that the --authorization-mode argument is not set to AlwaysAllow.

Low Priority

- [ ] Ensure that the --use-service-account-credentials argument is set to true.

- [ ] Ensure image tag is set in Kubernetes workload configuration.

- [ ] Ensure liveness probe is configured for containers in all Kubernetes workloads.

- [ ] Ensure readiness probe is configured for containers in all Kubernetes workloads.

- [ ] The default namespace should not be used.

- [ ] Ensure that the --profiling argument is set to false.


