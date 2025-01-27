import requests
import json
import urllib.parse

def login_and_get_session(server_url, username, password):
    login_endpoint = f"{server_url}/login"
    
    # Create a new session
    session = requests.Session()
    
    # Login data
    payload = {
        'username': username,
        'password': password
    }
    
    # Make the login request
    response = session.post(
        login_endpoint,
        data=payload,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    if response.status_code != 200:
        print(f"Login failed. Status code: {response.status_code}")
        print(f"Response content: {response.text}")
        raise Exception("Login failed")
    
    print("Login successful!")
    print(f"Session cookies: {session.cookies.get_dict()}")
    
    # Try an authenticated request to verify session
    test_response = session.get(f"{server_url}/active_boards")
    print(f"Session test response: {test_response.text}")
    print(f"Session test status: {test_response.status_code}")
    
    return session

def register_board(server_url, username, password, start_id, end_id, output_file):
    try:
        session = login_and_get_session(server_url, username, password)
        
        endpoint = f"{server_url}/register_device"
        registered_boards = []

        for esp_id in range(start_id, end_id + 1):
            esp_secret_key = f'esp_secret_key_{esp_id}'

            payload = {
                'esp_id': f'esp32_{esp_id}',
                'esp_secret_key': esp_secret_key
            }

            print(f"Making request with cookies: {session.cookies.get_dict()}")
            response = session.post(
                endpoint,
                data=payload,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.text}")

            if response.status_code == 200:
                print(f"ESP32 with ID 'esp32_{esp_id}' registered successfully!")
                registered_boards.append({
                    'esp_id': f'esp32_{esp_id}',
                    'esp_secret_key': esp_secret_key
                })
            else:
                print(f"Failed to register esp32_{esp_id}")
                break

        if registered_boards:
            with open(output_file, 'w') as outfile:
                json.dump(registered_boards, outfile, indent=4)
                print(f"Successfully registered {len(registered_boards)} boards!")

    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    server_url = 'http://localhost:5000'
    username = 'new_user'     # Replace with your actual username
    password = 'password123'  # Replace with your actual password
    start_id = 1
    end_id = 5
    output_file = 'registered_boards.json'

    register_board(server_url, username, password, start_id, end_id, output_file)