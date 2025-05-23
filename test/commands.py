import requests
import json
import random
import time
from http.cookiejar import MozillaCookieJar

# ANSI color codes for terminal output
class colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    END = '\033[0m'

# Function to read registered boards from JSON file
def read_registered_boards(filename):
    with open(filename, 'r') as f:
        boards = json.load(f)
    return boards

# Function to convert Netscape cookies to a dictionary
def parse_netscape_cookies(cookie_file):
    cookies = MozillaCookieJar(cookie_file)
    cookies.load()
    cookies_dict = {}
    for cookie in cookies:
        cookies_dict[cookie.name] = cookie.value
    return cookies_dict

# Function to send command to a specific board using cookies
def send_command_to_board_with_cookies(esp_id, command, cookies_file):
    url = 'http://localhost:5000/command'
    payload = {
        'esp_id': esp_id,
        'command': command
    }
    
    cookies_dict = parse_netscape_cookies(cookies_file)
    response = requests.post(url, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=payload, cookies=cookies_dict)
    if response.status_code == 200:
        print(f"{colors.GREEN}Sent command '{command}' to ESP board '{esp_id}' successfully.{colors.END}")
    else:
        print(f"{colors.RED}Error: Failed to send command to ESP board '{esp_id}'.{colors.END}")
    return esp_id, response

# Function to retrieve and verify command using esp_id and esp_secret_key
def retrieve_command_with_secret_key(esp_id, esp_secret_key):
    url = 'http://localhost:5000/get_command'
    params = {
        'esp_id': esp_id,
        'esp_secret_key': esp_secret_key
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        retrieved_command = data.get('command', '')
        print(" ")
        print(f"Retrieved command for ESP board '{esp_id}': '{retrieved_command}'")
        return esp_id, retrieved_command
    else:
        print(f"{colors.RED}Failed to retrieve command for ESP board '{esp_id}'. Response status: {response.status_code}{colors.END}")
    return None, None

# Main function to run the script
def main():
    boards = read_registered_boards('registered_boards.json')
    cookies_file = 'cookies.txt'
    requests_per_minute = 60  # Adjust as per your requirement
    seconds_per_request = 60 / requests_per_minute
    
    print(f"{colors.GREEN}=== Ghostkey Command Tester ==={colors.END}")
    print(f"Found {len(boards)} boards in the configuration.")
    
    while True:
        # Menu options
        print("\n" + "="*50)
        print("1. Select a random board and send command")
        print("2. Select a specific board and send command")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")
        
        if choice == '3':
            print("Exiting program...")
            break
            
        # Get command from user
        command = input("Enter the command to send: ")
        if not command:
            print(f"{colors.YELLOW}Command cannot be empty. Using default 'ping' command.{colors.END}")
            command = "ping"
            
        if choice == '1':
            # Select a random board
            board = random.choice(boards)
            esp_id = board['esp_id']
        elif choice == '2':
            # List all available boards
            print("\nAvailable boards:")
            for i, board in enumerate(boards):
                print(f"{i+1}. {board['esp_id']}")
                
            try:
                board_index = int(input("Select board number: ")) - 1
                if board_index < 0 or board_index >= len(boards):
                    print(f"{colors.YELLOW}Invalid selection. Using a random board.{colors.END}")
                    board = random.choice(boards)
                else:
                    board = boards[board_index]
            except ValueError:
                print(f"{colors.YELLOW}Invalid input. Using a random board.{colors.END}")
                board = random.choice(boards)
                
            esp_id = board['esp_id']
        else:
            print(f"{colors.YELLOW}Invalid choice. Please try again.{colors.END}")
            continue
            
        print(f"\nSending command '{command}' to board '{esp_id}'...")
        
        # Send command to the selected board
        esp_id_sent, send_response = send_command_to_board_with_cookies(esp_id, command, cookies_file)
        if send_response.status_code == 200:
            print(f"Waiting {seconds_per_request:.2f} seconds before retrieving command...")
            time.sleep(seconds_per_request)
            
            # Retrieve command for the same board
            esp_secret_key = board['esp_secret_key']
            esp_id_retrieved, retrieved_command = retrieve_command_with_secret_key(esp_id, esp_secret_key)
            if esp_id_retrieved == esp_id and retrieved_command == command:
                print(" ")
                print(f"{colors.GREEN}Verified: Retrieved command '{retrieved_command}' matches sent command for ESP board '{esp_id}'.{colors.END}")
            else:
                print(f"{colors.RED}Error: Retrieved command '{retrieved_command}' does not match sent command '{command}' for ESP board '{esp_id}'.{colors.END}")
                input(f"{colors.YELLOW}Press Enter to continue...{colors.END}")
        else:
            print(f"{colors.RED}Error: Failed to send command to ESP board '{esp_id}'.{colors.END}")
            input(f"{colors.YELLOW}Press Enter to continue...{colors.END}")

if __name__ == "__main__":
    main()
