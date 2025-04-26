# Real-time Shared Database Implementation for Ghostkey Server

## Overview

We've implemented a real-time shared database system for the Ghostkey Server that allows multiple server instances to work together as a cluster. This system provides:

1. **Real-time synchronization** of all changes across nodes via WebSockets
2. **Independent node operation** when network connectivity is lost
3. **Automatic data reconciliation** when nodes reconnect
4. **Conflict resolution** based on timestamps
5. **Scalable architecture** allowing new nodes to be added easily

## Implementation Details

### New Files Created

1. `sync.go` - Core WebSocket-based synchronization logic
2. `cluster.go` - Cluster management functions and entity change publishers
3. `docker-compose.cluster.yml` - Docker Compose file for running a 3-node cluster
4. `CLUSTER.md` - Documentation for the cluster mode
5. `run_cluster.sh` / `run_cluster.bat` - Helper scripts to run the cluster
6. `test/test_cluster.py` - Python script to test the cluster functionality
7. `cluster_examples.go` - Code examples showing how to use the cluster

### Modified Files

1. `models.go` - Added NodeID to GossipPayload
2. `main.go` - Added cluster initialization logic
3. `routes.go` - Added WebSocket and cluster status endpoints, integrated sync publishing
4. `config.json` - Added cluster configuration options
5. `README.md` - Added reference to cluster mode

### Key Components

#### 1. Real-time Event Synchronization (WebSockets)

The `sync.go` file implements a WebSocket-based event system that:
- Establishes connections between nodes
- Broadcasts entity changes in real-time
- Uses a dedicated broadcaster goroutine for efficient message distribution

#### 2. Conflict Resolution

The system uses timestamp-based conflict resolution:
- Each entity tracks its last update time
- When conflicts occur, the newer version wins
- Version vectors are used to determine the state of synchronization

#### 3. Entity Change Publication

The `cluster.go` file provides publisher functions that:
- Create sync events when entities are modified
- Queue events for broadcasting
- Convert entities to JSON for transmission

#### 4. Node Management

The cluster keeps track of:
- Active nodes in the cluster
- Connection status of each node
- Last seen timestamps for health monitoring

#### 5. Gossip Protocol Fallback

For reliability, the system continues to use the gossip protocol as a fallback:
- Periodic synchronization via HTTP requests
- Full state transfer for newly joined nodes
- Reconciliation of disconnected nodes

## How to Use

### Basic Setup (Single Node)

1. Use the default configuration (cluster_enabled: false)
2. Run the server as normal: `go run .`

### Cluster Setup

1. Update `config.json` to enable cluster mode:
   ```json
   {
     "server_interface": ":5000",
     "gossip_nodes": ["other-node:5000"],
     "node_id": "node-1",
     "cluster_enabled": true
   }
   ```

2. Run multiple nodes:
   - With Docker: `docker-compose -f docker-compose.cluster.yml up`
   - With scripts: `./run_cluster.sh` or `run_cluster.bat`
   
3. Test the cluster:
   - Run the test script: `python test/test_cluster.py`
   - Check cluster status: `http://localhost:5001/cluster/status`

## Integration Points

We've integrated the synchronization system with all key entity operations:

1. **User Management**
   - User registration triggers synchronization
   
2. **Device Management**
   - Device registration and removal are synchronized
   
3. **Command Operations**
   - Command creation and deletion are synchronized in real-time
   
4. **File Metadata**
   - File uploads trigger metadata synchronization
   
## Architecture Diagram

```
┌─────────────────┐         WebSocket         ┌─────────────────┐
│                 │◄────────Sync Events──────►│                 │
│    Node 1       │                           │     Node 2      │
│  (Primary DB)   │                           │  (Replica DB)   │
│                 │─────────HTTP/Gossip─────► │                 │
└────────┬────────┘                           └────────┬────────┘
         │                                             │
         │                                             │
         ▼                                             ▼
    ┌─────────┐                                   ┌─────────┐
    │ SQLite  │                                   │ SQLite  │
    │ DB 1    │                                   │ DB 2    │
    └─────────┘                                   └─────────┘
         ▲                                             ▲
         │              WebSocket                      │
         │            ┌───────────┐                    │
         └────────────┤  Node 3   ├────────────────────┘
                      │(Replica DB)│
                      └───────────┘
```

## Performance Considerations

1. The WebSocket approach is much more efficient than polling for changes
2. Database operations are done asynchronously where possible
3. The gossip protocol provides a reliable fallback for synchronization
4. Connection pooling reduces reconnection overhead

## Security Considerations

1. WebSocket connections should be secured with TLS in production
2. Node authentication should be implemented for cluster security
3. Encryption should be used for sensitive data in transit

## Future Improvements

1. **Leader Election**: Implement a leader election algorithm to designate a primary node
2. **Sharding**: Add support for partitioning data across nodes for better performance
3. **Persistent WebSocket**: Improve reconnection logic and session handling
4. **Data Compression**: Compress WebSocket payloads for reduced network usage
5. **Advanced Conflict Resolution**: Implement more sophisticated conflict resolution strategies

## Conclusion

This implementation provides a robust foundation for a distributed Ghostkey Server system that can scale horizontally while maintaining data consistency across all nodes. The real-time synchronization ensures that all nodes have up-to-date information, allowing for improved reliability and performance.
