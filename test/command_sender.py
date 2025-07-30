#!/usr/bin/env python3
import requests
import json
import time
import argparse
import random
from datetime import datetime
import os

# ANSI color codes for terminal output
class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

def log(message, color=None):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if color:
        print(f"{color}[{timestamp}] {message}{colors.END}")
    else:
        print(f"[{timestamp}] {message}")

# Function to read registered boards from JSON file
def read_registered_boards(filename):
    with open(filename, 'r') as f:
        boards = json.load(f)
    return boards

# Example commands that might be sent to ESP devices
SAMPLE_COMMANDS = [
    "led on",
    "led off",
    "read temperature",
    "read humidity",
    "status",
    "restart",
    "sleep 10",
    "capture image",
    "set interval 5",
    "run diagnostic",
    "update firmware",
    "clear memory",
    "set mode normal",
    "set mode low_power",
    "ping"
]

class CommandSender:
    def __init__(self, server_url="http://localhost:5000", auth_token=None, username=None, password=None):
        self.server_url = server_url
        self.auth_token = auth_token
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.headers = {}
        
        # If we have a token, set it in headers
        if self.auth_token:
            self.headers['Authorization'] = f'Bearer {self.auth_token}'
    
    def login(self):
        """Login to get session cookie"""
        if self.username and self.password:
            try:
                login_url = f"{self.server_url}/login"
                # The server expects form data, not JSON
                form_data = {
                    "username": self.username,
                    "password": self.password
                }
                log(f"Logging in as {self.username}...", colors.BLUE)
                
                # Send login request
                response = self.session.post(login_url, data=form_data)
                
                if response.status_code == 200:
                    # The session cookie will automatically be stored in self.session
                    log("Login successful - Session cookie received", colors.GREEN)
                    return True
                else:
                    log(f"Login failed: Status {response.status_code}", colors.RED)
                    log(f"Response: {response.text}", colors.RED)
                    return False
            except Exception as e:
                log(f"Error during login: {str(e)}", colors.RED)
                return False
                
        # If we have auth_token, set up basic auth
        elif self.auth_token:
            # Split the token if it's in the format username:password
            if ':' in self.auth_token:
                self.username, self.password = self.auth_token.split(':', 1)
                log(f"Using Basic Auth with provided token", colors.BLUE)
            # Set up basic auth in the session
            self.session.auth = (self.username, self.password)
            return True
            
        return False  # No authentication method available
    
    def get_devices(self):
        """Get list of registered devices from server"""
        try:
            url = f"{self.server_url}/active_boards"
            log("Fetching active devices from server...", colors.BLUE)
            response = self.session.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                active_boards = data.get('active_boards', [])
                log(f"Found {len(active_boards)} active devices", colors.GREEN)
                return active_boards
            else:
                log(f"Failed to fetch devices: Status {response.status_code}", colors.RED)
                if response.text:
                    log(f"Response: {response.text}", colors.RED)
                return []
        except Exception as e:
            log(f"Error fetching devices: {str(e)}", colors.RED)
            return []
    
    def send_command(self, esp_id, command):
        """Send a command to a specific device"""
        try:
            url = f"{self.server_url}/command"
            form_data = {
                "esp_id": esp_id,
                "command": command
            }
            
            log(f"Sending command '{command}' to ESP device {esp_id}...", colors.BLUE)
            response = self.session.post(url, data=form_data, headers=self.headers)
            
            if response.status_code == 200:
                log(f"Command '{command}' sent successfully to {esp_id}", colors.GREEN)
                return True
            else:
                log(f"Failed to send command: Status {response.status_code}", colors.RED)
                log(f"Response: {response.text}", colors.RED)
                return False
        except Exception as e:
            log(f"Error sending command: {str(e)}", colors.RED)
            return False
            
    def send_random_commands(self, boards, count=5, interval=3, random_interval=True):
        """Send random commands to random devices"""
        if not boards:
            log("No boards available to send commands to", colors.RED)
            return

        log(f"Starting random command sequence. Will send {count} commands...", colors.PURPLE)
        
        for i in range(count):
            # Select a random board and command
            board = random.choice(boards)
            command = random.choice(SAMPLE_COMMANDS)
            esp_id = board['esp_id']
            
            success = self.send_command(esp_id, command)
            
            # Determine sleep time with optional randomization
            if random_interval:
                sleep_time = random.uniform(interval * 0.5, interval * 1.5)
            else:
                sleep_time = interval
                
            # Only sleep if it's not the last command
            if i < count - 1:
                log(f"Waiting {sleep_time:.1f} seconds before next command...", colors.CYAN)
                time.sleep(sleep_time)
    
    def interactive_mode(self, boards):
        """Enter interactive mode to manually send commands"""
        if not boards:
            log("No boards available to send commands to", colors.RED)
            return
        
        board_dict = {str(i+1): board for i, board in enumerate(boards)}
        
        log("\n" + colors.PURPLE + "=== Interactive Command Mode ===" + colors.END)
        log("Available boards:")
        for idx, board in board_dict.items():
            log(f"  {idx}. ESP ID: {board['esp_id']}")
        
        log("\nCommands:")
        log("  'exit' or 'quit' - Exit interactive mode")
        log("  'list' - Show available boards")
        log("  'sample' - Show sample commands")
        log("  '<board_number> <command>' - Send command to specific board\n")
        
        while True:
            try:
                user_input = input(colors.BLUE + "Command > " + colors.END).strip()
                
                if user_input.lower() in ['exit', 'quit']:
                    log("Exiting interactive mode", colors.YELLOW)
                    break
                elif user_input.lower() == 'list':
                    log("Available boards:")
                    for idx, board in board_dict.items():
                        log(f"  {idx}. ESP ID: {board['esp_id']}")
                elif user_input.lower() == 'sample':
                    log("Sample commands:")
                    for cmd in SAMPLE_COMMANDS:
                        log(f"  {cmd}")
                else:
                    parts = user_input.split(' ', 1)
                    if len(parts) >= 2 and parts[0] in board_dict:
                        board_idx = parts[0]
                        command = parts[1]
                        esp_id = board_dict[board_idx]['esp_id']
                        self.send_command(esp_id, command)
                    else:
                        log("Invalid input format. Use '<board_number> <command>'", colors.YELLOW)
            except KeyboardInterrupt:
                log("\nExiting interactive mode", colors.YELLOW)
                break
            except Exception as e:
                log(f"Error: {str(e)}", colors.RED)

def main():
    parser = argparse.ArgumentParser(description='ESP Command Sender')
    parser.add_argument('--boards', type=str, default='registered_boards.json',
                        help='Path to the JSON file containing ESP board information')
    parser.add_argument('--server', type=str, default='http://localhost:5000',
                        help='Server URL to connect to')
    parser.add_argument('--token', type=str,
                        help='Authentication token for the server API')
    parser.add_argument('--username', type=str,
                        help='Username for server authentication')
    parser.add_argument('--password', type=str,
                        help='Password for server authentication')
    parser.add_argument('--count', type=int, default=5,
                        help='Number of random commands to send in auto mode')
    parser.add_argument('--interval', type=float, default=3,
                        help='Time between commands in seconds')
    parser.add_argument('--no-random-interval', action='store_true',
                        help='Disable random timing between commands')
    parser.add_argument('--interactive', action='store_true',
                        help='Run in interactive mode to manually send commands')
    
    args = parser.parse_args()
    
    # Create the command sender
    sender = CommandSender(
        server_url=args.server,
        auth_token=args.token,
        username=args.username,
        password=args.password
    )
    
    # Try to login if we have credentials but no token
    if not sender.auth_token and (sender.username and sender.password):
        if not sender.login():
            log("Authentication failed. Exiting.", colors.RED)
            return
    
    # Try to get boards from server API first
    boards = sender.get_devices()
    
    # If no boards from API, try to load from file
    if not boards:
        try:
            log("Attempting to load boards from local file...", colors.BLUE)
            boards = read_registered_boards(args.boards)
            log(f"Loaded {len(boards)} boards from file", colors.GREEN)
        except Exception as e:
            log(f"Error reading boards file: {str(e)}", colors.RED)
            return
    
    if not boards:
        log("No boards available. Please register boards first.", colors.RED)
        return
    
    print(f"{colors.GREEN}=== ESP Command Sender ==={colors.END}")
    print(f"Loaded {len(boards)} ESP devices")
    print(f"Server URL: {args.server}")
    
    try:
        if args.interactive:
            sender.interactive_mode(boards)
        else:
            sender.send_random_commands(
                boards, 
                count=args.count, 
                interval=args.interval, 
                random_interval=not args.no_random_interval
            )
    except KeyboardInterrupt:
        log("\nCommand sender stopped by user", colors.YELLOW)

if __name__ == "__main__":
    main()
