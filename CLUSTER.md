# Real-time Cluster Synchronization

This extension to the Ghostkey Server enables real-time synchronization between multiple server instances. This allows horizontal scaling and high availability without sacrificing data consistency.

## Features

- **Real-time Synchronization**: Changes to the database are propagated to all nodes in real-time using WebSockets.
- **Independent Operation**: Each node can work independently if network connectivity is lost.
- **Automatic Reconciliation**: When nodes reconnect, data is automatically synchronized.
- **Gossip Protocol**: Uses a gossip protocol for reliable data propagation across the cluster.
- **Conflict Resolution**: Uses timestamp-based conflict resolution to ensure data consistency.

## Usage

### Single Node Mode

By default, the server runs in single-node mode. No configuration is needed for this.

### Cluster Mode

To enable cluster mode, update your `config.json` file:

```json
{
    "server_interface": ":5000",
    "gossip_nodes": ["localhost:5002", "localhost:5003"],
    "node_id": "node-1",
    "cluster_enabled": true
}
```

Where:
- `gossip_nodes`: List of other node addresses in the format `host:port`
- `node_id`: A unique identifier for this node
- `cluster_enabled`: Set to `true` to enable cluster mode

### Docker Cluster Setup

For easy setup of a cluster with Docker, use the provided `docker-compose.cluster.yml`:

```shell
# Start a three-node cluster
docker-compose -f docker-compose.cluster.yml up
```

This will start three nodes with these endpoints:
- Node 1: http://localhost:5001
- Node 2: http://localhost:5002
- Node 3: http://localhost:5003

Each node operates independently but shares data with the others in real-time.

### Cluster Status API

To check the status of the cluster:

```shell
curl http://localhost:5001/cluster/status
```

Sample response:
```json
{
  "node_id": "node-1",
  "cluster_enabled": true,
  "nodes": [
    {
      "id": "node-1",
      "address": ":5000",
      "last_seen_at": "2025-04-26T15:04:05Z",
      "is_active": true,
      "ws_active": true
    },
    {
      "id": "node-2",
      "address": "node2:5000",
      "last_seen_at": "2025-04-26T15:03:59Z",
      "is_active": true,
      "ws_active": true
    },
    {
      "id": "node-3",
      "address": "node3:5000", 
      "last_seen_at": "2025-04-26T15:03:57Z",
      "is_active": true,
      "ws_active": true
    }
  ],
  "node_count": 3,
  "status": "healthy",
  "synchronized": true
}
```

## Architecture

The system uses a combination of WebSockets and HTTP for communication:

1. **WebSockets** for real-time event propagation
2. **HTTP** for gossip protocol fallback and initial sync
3. **SQLite** with database replication for persistence

## Adding a New Node

1. Create a new configuration file for the node with a unique `node_id`
2. Add the addresses of existing nodes to the `gossip_nodes` array
3. Set `cluster_enabled` to `true`
4. Start the new node
5. The node will automatically join the cluster and sync all data
