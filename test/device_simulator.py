#!/usr/bin/env python3
import requests
import json
import time
import random
import threading
import argparse
from datetime import datetime

# ANSI color codes for terminal output
class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

# Function to read registered boards from JSON file
def read_registered_boards(filename):
    with open(filename, 'r') as f:
        boards = json.load(f)
    return boards

# Function to simulate an ESP device behavior
class ESPDeviceSimulator(threading.Thread):
    def __init__(self, esp_id, esp_secret_key, server_url="http://localhost:5000", poll_interval=5, verbose=False):
        threading.Thread.__init__(self)
        self.esp_id = esp_id
        self.esp_secret_key = esp_secret_key
        self.server_url = server_url
        self.poll_interval = poll_interval
        self.verbose = verbose
        self.running = True
        self.last_command = None
        self.daemon = True  # Thread will exit when main program exits

    def log(self, message, color=None):
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if color:
                print(f"{color}[{timestamp}] ESP {self.esp_id}: {message}{colors.END}")
            else:
                print(f"[{timestamp}] ESP {self.esp_id}: {message}")

    def get_command(self):
        url = f"{self.server_url}/get_command"
        params = {
            'esp_id': self.esp_id,
            'esp_secret_key': self.esp_secret_key
        }
        try:
            self.log(f"Polling for commands...", colors.BLUE)
            response = requests.get(url, params=params)
            if response.status_code == 200:
                data = response.json()
                command = data.get('command', '')
                if command and command != self.last_command:
                    self.last_command = command
                    self.log(f"Received command: '{command}'", colors.GREEN)
                    # Simulate processing the command
                    self.process_command(command)
                    return command
                elif command == self.last_command and command:
                    self.log(f"Received same command again: '{command}'", colors.YELLOW)
                else:
                    self.log("No new commands", colors.CYAN)
            else:
                self.log(f"Error retrieving command: Status {response.status_code}", colors.RED)
        except Exception as e:
            self.log(f"Error connecting to server: {str(e)}", colors.RED)
        return None

    def process_command(self, command):
        # Simulate command processing
        self.log(f"Processing command: '{command}'", colors.PURPLE)
        processing_time = random.uniform(0.5, 2.0)
        time.sleep(processing_time)
        
        # Simulate sending a response to the command (if your system expects this)
        self.log(f"Command '{command}' executed successfully (simulated)", colors.GREEN)

        # Here you could add code to send a response back to the server if needed
        # For example:
        # self.send_response(command, "SUCCESS")

    def send_response(self, command, status):
        """Optional method to send a response back to the server after processing a command"""
        url = f"{self.server_url}/command_response"
        payload = {
            'esp_id': self.esp_id,
            'esp_secret_key': self.esp_secret_key,
            'command': command,
            'status': status
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                self.log(f"Response for '{command}' sent successfully", colors.GREEN)
            else:
                self.log(f"Failed to send response: Status {response.status_code}", colors.RED)
        except Exception as e:
            self.log(f"Error sending response: {str(e)}", colors.RED)

    def run(self):
        self.log(f"Device simulator started", colors.GREEN)
        failures = 0
        max_failures = 5
        
        while self.running:
            try:
                self.get_command()
                failures = 0  # Reset failure count on success
            except Exception as e:
                self.log(f"Error in device simulation loop: {str(e)}", colors.RED)
                failures += 1
                if failures >= max_failures:
                    self.log(f"Too many consecutive failures. Stopping device simulator.", colors.RED)
                    break
            
            # Random jitter to avoid synchronized polling
            jitter = random.uniform(-1.0, 1.0)
            sleep_time = max(1, self.poll_interval + jitter)
            time.sleep(sleep_time)

    def stop(self):
        self.running = False
        self.log("Stopping device simulator...", colors.YELLOW)

def main():
    parser = argparse.ArgumentParser(description='ESP Device Simulator')
    parser.add_argument('--boards', type=str, default='registered_boards.json',
                        help='Path to the JSON file containing ESP board information')
    parser.add_argument('--server', type=str, default='http://localhost:5000',
                        help='Server URL to connect to')
    parser.add_argument('--devices', type=int, default=0,
                        help='Number of devices to simulate (0 means all from the boards file)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Poll interval in seconds')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    try:
        boards = read_registered_boards(args.boards)
    except Exception as e:
        print(f"{colors.RED}Error reading boards file: {str(e)}{colors.END}")
        return
    
    num_devices = min(args.devices, len(boards)) if args.devices > 0 else len(boards)
    print(f"{colors.GREEN}=== ESP Device Simulator ==={colors.END}")
    print(f"Starting {num_devices} device simulators")
    print(f"Server URL: {args.server}")
    print(f"Poll interval: {args.interval} seconds")
    
    # Create and start device simulator threads
    simulators = []
    for i in range(num_devices):
        board = boards[i]
        simulator = ESPDeviceSimulator(
            board['esp_id'],
            board['esp_secret_key'],
            server_url=args.server,
            poll_interval=args.interval,
            verbose=args.verbose
        )
        simulators.append(simulator)
        simulator.start()
        print(f"Started simulator for ESP device: {board['esp_id']}")
    
    try:
        print(f"\n{colors.YELLOW}Press Ctrl+C to stop the simulators{colors.END}")
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{colors.YELLOW}Stopping all simulators...{colors.END}")
        for simulator in simulators:
            simulator.stop()
        
        # Give threads time to cleanly exit
        time.sleep(1)
        print(f"{colors.GREEN}All simulators stopped.{colors.END}")

if __name__ == "__main__":
    main()
