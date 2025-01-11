# Container Forensics and Investigation Guide

## Table of Contents
1. [Initial Response](#initial-response)
2. [Live Container Analysis](#live-container-analysis)
3. [Evidence Collection](#evidence-collection)
4. [Container Image Analysis](#container-image-analysis)
5. [Network Forensics](#network-forensics)
6. [Storage Investigation](#storage-investigation)
7. [Memory Analysis](#memory-analysis)
8. [Common Investigation Scenarios](#common-investigation-scenarios)

## Initial Response

### Container Status Commands
```bash
# List all running containers
docker ps

# List all containers (including stopped)
docker ps -a

# Show detailed container information
docker inspect <container_id>

# View container logs
docker logs <container_id>

# View real-time container logs
docker logs -f <container_id>
```

### Process Investigation
```bash
# View processes inside container
docker top <container_id>

# Get container statistics
docker stats <container_id>

# Execute process listing inside container
docker exec <container_id> ps aux

# View host processes related to container
ps aux | grep <container_id>
```

## Live Container Analysis

### System Information
```bash
# Get container resource usage
docker stats <container_id> --no-stream

# View container details
docker inspect <container_id> | grep -i ip
docker inspect <container_id> | grep -i mac
docker inspect <container_id> | grep -i network

# Check container mounts
docker inspect <container_id> | grep -i mount
```

### Live Investigation Commands
```bash
# Enter running container
docker exec -it <container_id> /bin/bash

# Check running processes
docker exec <container_id> ps -ef

# View network connections
docker exec <container_id> netstat -anlp

# Check open files
docker exec <container_id> lsof

# View loaded kernel modules
docker exec <container_id> lsmod
```

## Evidence Collection

### Container Filesystem
```bash
# Export container filesystem
docker export <container_id> > container_fs.tar

# Create container image from container
docker commit <container_id> forensic_image

# Save container image
docker save forensic_image > forensic_image.tar

# Extract specific files
docker cp <container_id>:/path/to/file /host/path/
```

### Metadata Collection
```bash
# Collect container metadata
docker inspect <container_id> > container_metadata.json

# Get container creation time
docker inspect <container_id> | grep -i created

# Export container logs
docker logs <container_id> > container_logs.txt

# Get container changes
docker diff <container_id>
```

## Container Image Analysis

### Image Investigation
```bash
# List all images
docker images

# Show image history
docker history <image_id>

# Inspect image configuration
docker inspect <image_id>

# Extract image layers
docker save <image_id> | tar -xf -

# Analyze image manifest
tar -xf image.tar manifest.json -O | python -m json.tool
```

## Network Forensics

### Network Analysis
```bash
# View container network settings
docker network ls
docker network inspect <network_id>

# Capture network traffic
tcpdump -i docker0 -w capture.pcap

# Monitor container network connections
docker exec <container_id> netstat -tupn

# Check DNS resolution
docker exec <container_id> dig <domain>

# Trace network routes
docker exec <container_id> traceroute <destination>
```

## Storage Investigation

### Volume Analysis
```bash
# List volumes
docker volume ls

# Inspect volume
docker volume inspect <volume_name>

# Copy volume data
cp -r /var/lib/docker/volumes/<volume_name>/_data /evidence/

# Check volume mounts
docker inspect <container_id> | grep -A 10 Mounts
```

## Memory Analysis

### Memory Capture
```bash
# Capture container memory
docker checkpoint create <container_id> checkpoint1

# Use CRIU for memory dumps
criu dump -t <container_pid> -D memory_dump/

# Memory analysis with volatility
vol.py -f memory_dump linux_pslist
```

## Common Investigation Scenarios

### Compromised Container Investigation
```bash
# Check for unauthorized processes
docker top <container_id>
docker exec <container_id> ps aux

# Look for unexpected network connections
docker exec <container_id> netstat -anlp

# Check for filesystem changes
docker diff <container_id>

# Review recent commands
docker exec <container_id> history

# Check for unauthorized users
docker exec <container_id> cat /etc/passwd
```

### Malware Investigation
```bash
# Check for suspicious processes
docker exec <container_id> ps aux --sort -%cpu

# Look for hidden files
docker exec <container_id> find / -type f -name ".*"

# Check for modified binaries
docker exec <container_id> debsums -c

# Scan for malware
docker exec <container_id> clamscan -r /
```

### Data Exfiltration Investigation
```bash
# Monitor network traffic
tcpdump -i docker0 -w capture.pcap

# Check outbound connections
docker exec <container_id> netstat -anp | grep ESTABLISHED

# Review DNS queries
docker exec <container_id> tcpdump -i any -l port 53

# Check for unauthorized data access
docker exec <container_id> aureport -f
```

