# Kubernetes DFIR Field Guide

> **Time Sensitivity**: K8s forensics operates on three time horizons: immediate (running containers), short-term (node state), and persistent (control plane logs). Structure your investigation accordingly.

## First Response (0-30 minutes)

Preserve volatile evidence first:
```bash
# Cluster state snapshot
kubectl get all -A -o yaml > $(date +%Y%m%d_%H%M)_cluster.yaml

# Critical container preservation
for pod in $(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'); do
  ns=${pod% *}
  name=${pod#* }
  kubectl -n $ns logs $pod --all-containers > ${ns}_${name}_$(date +%Y%m%d_%H%M).log
  kubectl -n $ns get pod $name -o yaml > ${ns}_${name}_$(date +%Y%m%d_%H%M).yaml
done
```

> **Evidence Hierarchy**: Prioritize ephemeral container state before focusing on persistent storage. Memory first, disk second.

## Control Plane Analysis

API server provides the truth source for cluster operations:
```bash
# Comprehensive audit trail
journalctl -u kube-apiserver --since "1 hour ago" -o json > \
  apiserver_$(date +%Y%m%d_%H%M).json

# State database backup
ETCDCTL_API=3 etcdctl snapshot save etcd_$(date +%Y%m%d_%H%M).db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key
```

## Node-Level Investigation

Worker nodes contain crucial runtime context:
```bash
# Deploy forensic toolkit to target node
NODE="target-node"
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: forensic-toolkit
spec:
  nodeName: ${NODE}
  hostPID: true
  hostNetwork: true
  containers:
  - name: toolkit
    image: nicolaka/netshoot
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
    command: ["sleep", "infinity"]
  volumes:
  - name: host
    hostPath:
      path: /
EOF

# Collect node artifacts
kubectl exec -it forensic-toolkit -- /bin/sh -c '
  cd /host
  tar czf /tmp/node_$(hostname)_$(date +%Y%m%d_%H%M).tar.gz \
    var/log \
    etc/kubernetes \
    var/lib/kubelet
'
```

## Memory Acquisition

Capture volatile memory state:
```bash
# Container memory dump
PID=$(docker inspect --format '{{.State.Pid}}' $CONTAINER_ID)
gdb --pid $PID --batch -ex "dump memory container_${PID}_$(date +%Y%m%d_%H%M).raw 0x00000000 0xffffffff"

# Preserve memory context
cp -r /proc/$PID/maps proc_maps_${PID}_$(date +%Y%m%d_%H%M).txt
cp -r /proc/$PID/fd fd_${PID}_$(date +%Y%m%d_%H%M)/
```

## Network Forensics

Deploy network capture infrastructure:
```bash
# Network forensics DaemonSet
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: capture
spec:
  selector:
    matchLabels:
      app: capture
  template:
    metadata:
      labels:
        app: capture
    spec:
      hostNetwork: true
      containers:
      - name: tcpdump
        image: nicolaka/netshoot
        command: ["/bin/sh"]
        args:
        - -c
        - |
          tcpdump -i any -w /cap/$(hostname)_$(date +%Y%m%d_%H%M).pcap
        volumeMounts:
        - name: capture-storage
          mountPath: /cap
      volumes:
      - name: capture-storage
        hostPath:
          path: /var/log/capture
EOF
```

## Anti-Forensics Detection

Monitor for evidence tampering:
```bash
# Track pod termination patterns
kubectl get events --field-selector reason=Killing \
  -o json | jq '.items[] | select(.message | contains("OOMKilled") | not)'

# Monitor volume manipulation
kubectl get pods -o json | jq '.items[] | 
  select(.spec.volumes[]?.emptyDir != null) | 
  {name: .metadata.name, 
   namespace: .metadata.namespace, 
   volumes: .spec.volumes}'
```

## Essential Toolkit

Core tools by investigation phase:

1. **Initial Response**
   - kubectl (cluster interaction)
   - jq (JSON parsing)
   - tcpdump (network capture)

2. **Deep Analysis**
   - sysdig (system visibility)
   - gdb (memory analysis)
   - osquery (host investigation)

3. **Continuous Monitoring**
   - falco (runtime security)
   - tracee (syscall monitoring)
   - kubeaudit (configuration analysis)

## Chain of Custody

Document everything:
```bash
# Start investigation log
script -a investigation_$(date +%Y%m%d_%H%M).log
date
kubectl config current-context
whoami

# Hash all evidence
find . -type f -name "*$(date +%Y%m%d)*" -exec sha256sum {} \; > hashes_$(date +%Y%m%d_%H%M).txt
```

> **Investigation Pattern**: Always move from volatile to persistent evidence. Container memory → Node state → Control plane logs → Persistent storage.
