#!/usr/bin/env python3
# test_cluster.py - Script to test GhostkeyServer cluster setup

import requests
import time
import json
import sys
import random
import threading
from concurrent.futures import ThreadPoolExecutor

# Default ports for nodes
NODE_PORTS = [5001, 5002, 5003]

# Commands to test with
SAMPLE_COMMANDS = [
    "test_command_1",
    "reboot",
    "collect_data",
    "send_report",
    "update_firmware",
    "scan_network",
    "execute_payload",
    "clear_logs",
]

def check_node_health(port):
    """Check if a node is healthy"""
    try:
        resp = requests.get(f"http://localhost:{port}/health", timeout=2)
        if resp.status_code == 200:
            return True
        return False
    except Exception:
        return False

def get_cluster_status(port):
    """Get the cluster status from a node"""
    try:
        resp = requests.get(f"http://localhost:{port}/cluster/status", timeout=2)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None

def register_user(port, username, password):
    """Register a new user"""
    try:
        resp = requests.post(
            f"http://localhost:{port}/register_user",
            data={
                "username": username,
                "password": password,
                "secret_key": "test_secret_key"
            }
        )
        return resp.status_code == 200
    except Exception:
        return False

def login(port, username, password):
    """Login to get a session cookie"""
    try:
        resp = requests.post(
            f"http://localhost:{port}/login",
            data={
                "username": username,
                "password": password
            }
        )
        if resp.status_code == 200:
            return resp.cookies
        return None
    except Exception:
        return None

def register_device(port, cookies, esp_id):
    """Register a new device"""
    try:
        resp = requests.post(
            f"http://localhost:{port}/register_device",
            cookies=cookies,
            data={
                "esp_id": esp_id,
                "esp_secret_key": "device_secret"
            }
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"Error registering device: {e}")
        return False

def add_command(port, cookies, esp_id, command):
    """Add a command for a device"""
    try:
        resp = requests.post(
            f"http://localhost:{port}/command",
            cookies=cookies,
            data={
                "esp_id": esp_id,
                "command": command
            }
        )
        return resp.status_code == 200
    except Exception:
        return False

def get_commands(port, esp_id):
    """Get all commands for a device"""
    try:
        resp = requests.get(
            f"http://localhost:{port}/get_all_commands?esp_id={esp_id}",
            cookies=login(port, "testuser", "password123")
        )
        if resp.status_code == 200:
            return resp.json().get("commands", [])
        return []
    except Exception:
        return []

def print_separator():
    print("-" * 80)

def check_data_sync(ports, esp_id):
    """Check if data is synced across all nodes"""
    commands_by_node = {}
    
    for port in ports:
        commands = get_commands(port, esp_id)
        command_texts = [cmd.get("command") for cmd in commands]
        commands_by_node[port] = set(command_texts)
    
    # Check if all nodes have the same commands
    first_node = ports[0]
    first_node_commands = commands_by_node[first_node]
    
    all_in_sync = True
    for port in ports[1:]:
        if commands_by_node[port] != first_node_commands:
            all_in_sync = False
            break
    
    return all_in_sync, commands_by_node

def main():
    print("Ghostkey Server Cluster Test")
    print_separator()
    
    # Check if all nodes are up
    available_nodes = []
    for port in NODE_PORTS:
        if check_node_health(port):
            available_nodes.append(port)
            print(f"Node at port {port} is available")
        else:
            print(f"Node at port {port} is NOT available")
    
    if not available_nodes:
        print("No nodes available. Please start the cluster.")
        sys.exit(1)
    
    print_separator()
    print(f"Testing with {len(available_nodes)} available nodes")
    
    # Get cluster status from first node
    status = get_cluster_status(available_nodes[0])
    if status:
        print(f"Cluster status from node at port {available_nodes[0]}:")
        print(f"  Node ID: {status.get('node_id')}")
        print(f"  Cluster enabled: {status.get('cluster_enabled')}")
        print(f"  Nodes in cluster: {status.get('node_count')}")
        print(f"  Synchronized: {status.get('synchronized')}")
    else:
        print("Could not get cluster status")
    
    print_separator()
    print("Registering test user on first node...")
    
    # Register test user on first node
    if register_user(available_nodes[0], "testuser", "password123"):
        print("User registered successfully")
    else:
        print("User registration failed or user already exists")
    
    # Login to the first node
    cookies = login(available_nodes[0], "testuser", "password123")
    if not cookies:
        print("Login failed. Exiting.")
        sys.exit(1)
    
    print("Logged in successfully")
    
    # Register test device on first node
    esp_id = f"test_esp_{int(time.time())}"
    print(f"Registering device {esp_id} on node at port {available_nodes[0]}...")
    
    if register_device(available_nodes[0], cookies, esp_id):
        print("Device registered successfully")
    else:
        print("Device registration failed")
        sys.exit(1)
    
    print_separator()
    print("Adding commands to random nodes...")
    
    # Add commands to random nodes
    for i in range(10):
        port = random.choice(available_nodes)
        command = random.choice(SAMPLE_COMMANDS)
        node_cookies = login(port, "testuser", "password123")
        
        if add_command(port, node_cookies, esp_id, f"{command}_{i}"):
            print(f"Added command '{command}_{i}' to node at port {port}")
        else:
            print(f"Failed to add command to node at port {port}")
    
    # Wait for sync
    print("Waiting for sync (5 seconds)...")
    time.sleep(5)
    
    print_separator()
    print("Checking command synchronization...")
    
    # Check if commands are synced
    synced, commands_by_node = check_data_sync(available_nodes, esp_id)
    
    if synced:
        print("All nodes are in sync!")
        
        # Print commands from the first node
        first_node = available_nodes[0]
        print(f"Commands on all nodes:")
        for cmd in sorted(list(commands_by_node[first_node])):
            print(f"  - {cmd}")
    else:
        print("Nodes are NOT in sync!")
        for port, commands in commands_by_node.items():
            print(f"Commands on node at port {port}:")
            for cmd in sorted(list(commands)):
                print(f"  - {cmd}")
    
    print_separator()
    print("Test completed")

if __name__ == "__main__":
    main()
