import requests
from cryptography.fernet import Fernet
import os

KEY_FILE_PATH = 'key.key'
LOG_FILE_PATH = 'secure_log.enc'

# Function to load the key from the file
def load_key():
    with open(KEY_FILE_PATH, 'rb') as key_file:
        key = key_file.read()
    return key

key = load_key()
cipher_suite = Fernet(key)

def transmit_data(file_path, server_url):
    with open(file_path, 'rb') as file:
        encrypted_lines = file.readlines()
    
    decrypted_data = ""
    for line in encrypted_lines:
        decrypted_data += cipher_suite.decrypt(line).decode()
    
    response = requests.post(server_url, json={"data": decrypted_data})
    return response.status_code

# Example usage
if __name__ == "__main__":
    # Change the server URL to your local server's address
    server_url = "http://localhost:5000/upload"
    file_path = LOG_FILE_PATH
    status = transmit_data(file_path, server_url)
    print(f"Data transmitted, status code: {status}")
