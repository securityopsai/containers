# Container Investigation Guide: Application-Centric Approach

> **Container Workload**: The primary application and its supporting processes running within a container, representing the container's core purpose and expected behavior pattern.

## Common Container Patterns and Their Investigation

Modern containers typically fall into several distinct patterns, each with unique investigation approaches:

### Web Application Containers

These represent the most common container workload - Node.js, Python, Java, or PHP applications serving HTTP(S) traffic.

```bash
# Normal behavior baseline
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' $CONTAINER_ID)

# Expected process patterns
ps aux | grep -E "node|python|java|php-fpm"

# Normal port bindings
netstat -tulpn | grep -E ':80|:443|:3000|:8080'

# Suspicious indicators
# 1. Unexpected child processes
ps -ef --forest | grep $CONTAINER_PID

# 2. Unusual network connections (application specific)
netstat -an | grep -v -E ':80|:443|:3000|:8080|:27017'

# 3. File modifications in app directories
OVERLAY_DIR=$(docker inspect $CONTAINER_ID | jq -r '.[0].GraphDriver.Data.MergedDir')
find $OVERLAY_DIR -type f -mtime -1 -not -path "*/node_modules/*" -not -path "*/logs/*"
```

### Database Containers

Databases in containers have very predictable behavioral patterns, making anomaly detection straightforward:

```bash
# PostgreSQL investigation
if [[ $(docker inspect $CONTAINER_ID | grep -i postgres) ]]; then
    # Check for normal ports (5432)
    netstat -tulpn | grep -v ':5432'
    
    # Examine data directory changes
    find /var/lib/postgresql/data -type f -mtime -1
    
    # Look for unexpected processes
    ps aux | grep -v -E "postgres:|logger:|stats"
fi

# MongoDB patterns
if [[ $(docker inspect $CONTAINER_ID | grep -i mongo) ]]; then
    # Default port 27017
    netstat -tulpn | grep -v ':27017'
    
    # Deep database investigation
    mongosh --quiet --eval '
        // List all databases
        db.adminCommand("listDatabases").databases.forEach(db => {
            print(`Database: ${db.name}, Size: ${db.sizeOnDisk}`);
            // Check for unexpected collections
            use(db.name);
            db.getCollectionNames().forEach(col => {
                if (!col.match(/^(system\.|admin\.|local\.)/)) {
                    print(`  Collection: ${col}`);
                    // Check for recent modifications
                    print(`    Recent updates: ${db[col].count({"updateTime": {$gt: new Date(Date.now() - 3600000)}})}`)
                }
            });
        });
    '
fi
```

### API/Microservice Containers

Typically lightweight, single-process containers with specific network patterns:

```bash
# Process investigation
# Should typically show single main process
ps aux --forest | grep $CONTAINER_PID

# Service mesh investigation
# Common ports and patterns:
# - Istio sidecar: 15000-15999 (especially 15090 for Prometheus)
# - Linkerd: 4140-4191
# - Consul: 8300-8600
# - Application metrics: 9090-9091
netstat -tulpn | grep -E ':(15090|4140|8500|9090)'

# Proxy sidecar validation
ps aux | grep -E '(envoy|linkerd|consul)-proxy'

# Health check validation
for port in $(netstat -tulpn | grep LISTEN | awk '{print $4}' | cut -d: -f2); do
    curl -sf localhost:$port/health && echo "Health check OK on $port" || true
    curl -sf localhost:$port/metrics && echo "Metrics OK on $port" || true
done

# Suspicious activities
netstat -an | grep ESTABLISHED | grep -v -E ':(9000|9090|9091)'
```

### Message Queue Containers

RabbitMQ, Redis, and similar message brokers have distinct patterns:

```bash
# RabbitMQ investigation
if [[ $(docker inspect $CONTAINER_ID | grep -i rabbit) ]]; then
    # Expected ports: 5672 (AMQP), 15672 (management)
    netstat -tulpn | grep -v -E ':5672|:15672'
    
    # Check for unexpected queue creation
    rabbitmqctl list_queues | grep -v -E "^(celery|events|notifications)"
fi

# Redis patterns
if [[ $(docker inspect $CONTAINER_ID | grep -i redis) ]]; then
    # Default port 6379
    netstat -an | grep -v ':6379'
    
    # Monitor commands in real-time
    redis-cli monitor | grep -v -E "GET|SET|LPUSH|RPOP"
fi
```

### Static Content/CDN Containers

Nginx/Apache containers serving static content:

```bash
# Nginx patterns
if [[ $(docker inspect $CONTAINER_ID | grep -i nginx) ]]; then
    # File modification in content directories
    find /usr/share/nginx/html -type f -mtime -1
    
    # Access log pattern analysis
    tail -f /var/log/nginx/access.log | grep -v -E '\.(jpg|png|css|js|gif)'
fi
```

## Behavioral Analysis by Container Type

> **Process Hierarchy**: The expected parent-child relationship between processes in a container, which should remain consistent throughout the container's lifecycle.

### Development Tools Containers

```bash
# Jenkins container investigation
if [[ $(docker inspect $CONTAINER_ID | grep -i jenkins) ]]; then
    # Check for unexpected build processes
    ps aux | grep -v -E "jenkins|java|git"
    
    # Examine workspace changes
    find /var/jenkins_home/workspace -type f -mtime -1
fi
```

### Cache Containers

```bash
# Memcached/Redis investigation
netstat -an | grep -v -E ':6379|:11211'
ps aux | grep -v -E 'redis-server|memcached'
```

## Investigation Workflows

### 1. Application-Specific Baseline

First, identify the container's intended purpose:

```bash
# Get container metadata
docker inspect $CONTAINER_ID | grep -i "image"

# Determine main process
ps -p $(docker inspect -f '{{.State.Pid}}' $CONTAINER_ID) -o comm=

# Check expected ports
docker port $CONTAINER_ID
```

### 2. Workload-Specific Analysis

```bash
#!/bin/bash
# Analyze based on container type
CONTAINER_TYPE=$(docker inspect $CONTAINER_ID | grep -i -E 'nginx|node|python|java|postgres|redis')

case $CONTAINER_TYPE in
    *nginx*)
        # Web server analysis
        check_web_server_patterns
        ;;
    *node*)
        # Node.js application analysis
        check_node_patterns
        ;;
    *postgres*)
        # Database analysis
        check_database_patterns
        ;;
esac
```

### 3. Resource Usage Patterns

Different container types have distinct resource patterns:

```bash
# Get baseline metrics
docker stats --no-stream $CONTAINER_ID

# Process-specific metrics
pidstat -p $(docker inspect -f '{{.State.Pid}}' $CONTAINER_ID) 1

# Container cgroup analysis
cat /sys/fs/cgroup/cpu/docker/$CONTAINER_ID/cpu.stat
```

Remember: Container investigation should always start with understanding the container's intended purpose and normal behavior patterns. Anomaly detection becomes much more accurate when baselined against expected application-specific patterns rather than generic system metrics.