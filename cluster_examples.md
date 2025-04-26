# Ghostkey Server Cluster Examples

This file contains usage examples for the real-time synchronization feature of the Ghostkey Server.

## 1. Initialize a cluster with 3 nodes in Go

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "github.com/gin-gonic/gin"
)

func main() {
    // Set environment variables
    os.Setenv("SECRET_KEY", "test_secret_key")

    // Start 3 nodes in separate goroutines
    var wg sync.WaitGroup
    wg.Add(3)

    // Node 1
    go func() {
        defer wg.Done()
        config := `{
            "server_interface": ":5001",
            "gossip_nodes": ["localhost:5002", "localhost:5003"],
            "node_id": "node-1",
            "cluster_enabled": true
        }`
        
        // Write config to file
        os.WriteFile("config1.json", []byte(config), 0644)
        
        // Run the server with this config
        // In a real implementation, you would need to modify main.go to accept
        // a custom config file path, or set all these parameters programmatically
        fmt.Println("Starting node 1 on port 5001")
        // startServer("config1.json")
    }()

    // Node 2
    go func() {
        defer wg.Done()
        config := `{
            "server_interface": ":5002",
            "gossip_nodes": ["localhost:5001", "localhost:5003"],
            "node_id": "node-2",
            "cluster_enabled": true
        }`
        
        // Write config to file
        os.WriteFile("config2.json", []byte(config), 0644)
        
        fmt.Println("Starting node 2 on port 5002")
        // startServer("config2.json")
    }()

    // Node 3
    go func() {
        defer wg.Done()
        config := `{
            "server_interface": ":5003",
            "gossip_nodes": ["localhost:5001", "localhost:5002"],
            "node_id": "node-3",
            "cluster_enabled": true
        }`
        
        // Write config to file
        os.WriteFile("config3.json", []byte(config), 0644)
        
        fmt.Println("Starting node 3 on port 5003")
        // startServer("config3.json")
    }()

    // Wait for all nodes to start
    wg.Wait()

    // The server will keep running until Ctrl+C is pressed
    fmt.Println("All nodes started. Press Ctrl+C to stop.")
    
    // Wait indefinitely
    select {}
}
```

## 2. Client-side code to interact with the cluster (JavaScript)

```javascript
// Connect to WebSocket for real-time updates
const ws = new WebSocket('ws://localhost:5001/ws');

ws.onopen = () => {
    console.log('Connected to Ghostkey Server cluster');
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received update:', data);
    
    // Handle different types of events
    switch (data.type) {
        case 'command':
            console.log(`Command ${data.action}d: ${data.data.command}`);
            break;
        case 'device':
            console.log(`Device ${data.action}d: ${data.data.esp_id}`);
            break;
        case 'user':
            console.log(`User ${data.action}d: ${data.data.username}`);
            break;
        case 'file':
            console.log(`File ${data.action}d: ${data.data.file_name}`);
            break;
    }
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = () => {
    console.log('Disconnected from Ghostkey Server');
    // Attempt to reconnect after a delay
    setTimeout(() => {
        console.log('Attempting to reconnect...');
        // Reconnect logic here
    }, 5000);
};

// Function to send commands
async function sendCommand(espId, command) {
    try {
        const response = await fetch('http://localhost:5001/command', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `esp_id=${encodeURIComponent(espId)}&command=${encodeURIComponent(command)}`,
            credentials: 'include',
        });
        
        if (response.ok) {
            console.log('Command sent successfully');
            return true;
        } else {
            console.error('Failed to send command:', await response.text());
            return false;
        }
    } catch (error) {
        console.error('Error sending command:', error);
        return false;
    }
}

// Example usage
sendCommand('esp32_1', 'reboot');
```

## 3. Python example for interacting with the cluster

```python
import requests
import json
import websocket
import threading
import time

# Function to listen for WebSocket updates
def ws_listener():
    def on_message(ws, message):
        data = json.loads(message)
        print(f"Received update: {data}")
        
        # Handle different types of events
        if data.get('type') == 'command':
            print(f"Command {data.get('action')}d: {data.get('data', {}).get('command')}")
        elif data.get('type') == 'device':
            print(f"Device {data.get('action')}d: {data.get('data', {}).get('esp_id')}")
    
    def on_error(ws, error):
        print(f"WebSocket error: {error}")
    
    def on_close(ws, close_status_code, close_msg):
        print("WebSocket connection closed")
        # Attempt to reconnect after a delay
        time.sleep(5)
        print("Attempting to reconnect...")
        start_websocket()
    
    def on_open(ws):
        print("WebSocket connection opened")
    
    def start_websocket():
        websocket.enableTrace(False)
        ws = websocket.WebSocketApp("ws://localhost:5001/ws",
                                   on_message=on_message,
                                   on_error=on_error,
                                   on_close=on_close)
        ws.on_open = on_open
        ws.run_forever()
    
    # Start the WebSocket connection in a separate thread
    ws_thread = threading.Thread(target=start_websocket)
    ws_thread.daemon = True
    ws_thread.start()
    return ws_thread

# Start the WebSocket listener
ws_thread = ws_listener()

# Function to send a command
def send_command(esp_id, command, port=5001):
    try:
        response = requests.post(
            f"http://localhost:{port}/command",
            data={
                "esp_id": esp_id,
                "command": command
            },
            cookies=get_session_cookies(port)
        )
        if response.status_code == 200:
            print(f"Command sent successfully through port {port}")
            return True
        else:
            print(f"Failed to send command through port {port}: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending command: {e}")
        return False

# Function to get session cookies (after login)
def get_session_cookies(port=5001):
    response = requests.post(
        f"http://localhost:{port}/login",
        data={
            "username": "testuser",
            "password": "password123"
        }
    )
    if response.status_code == 200:
        return response.cookies
    return None

# Register a user if needed
def register_user(port=5001):
    response = requests.post(
        f"http://localhost:{port}/register_user",
        data={
            "username": "testuser",
            "password": "password123",
            "secret_key": "test_secret_key"
        }
    )
    return response.status_code == 200

# Register a device
def register_device(esp_id, port=5001):
    cookies = get_session_cookies(port)
    if not cookies:
        print("Failed to get session cookies")
        return False
    
    response = requests.post(
        f"http://localhost:{port}/register_device",
        cookies=cookies,
        data={
            "esp_id": esp_id,
            "esp_secret_key": "device_secret"
        }
    )
    return response.status_code == 200

# Example usage
if __name__ == "__main__":
    # First register a user (if not already registered)
    register_user()
    
    # Register a device
    esp_id = "test_esp_device"
    register_device(esp_id)
    
    # Send some commands through different nodes
    send_command(esp_id, "command_1", 5001)
    send_command(esp_id, "command_2", 5002)
    send_command(esp_id, "command_3", 5003)
    
    # Keep the script running to receive WebSocket updates
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
```
