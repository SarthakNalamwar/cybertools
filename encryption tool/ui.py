import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from encryption import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_encrypt, rsa_decrypt
from key_management import generate_aes_key, generate_des_key, generate_rsa_keys, generate_salt
from file_handling import read_file, write_file, read_binary_file, write_binary_file
from user_auth import authenticate
from utils import log_info, log_error
from Crypto.PublicKey import RSA

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption App")

        # User Authentication Frame
        self.auth_frame = ttk.LabelFrame(root, text="User Authentication")
        self.auth_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.username_label = ttk.Label(self.auth_frame, text="Username:")
        self.username_label.grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.auth_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        self.password_label = ttk.Label(self.auth_frame, text="Password:")
        self.password_label.grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.auth_frame, show='*')
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Algorithm Selection Frame
        self.alg_frame = ttk.LabelFrame(root, text="Select Algorithm")
        self.alg_frame.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

        self.algorithm = tk.StringVar()
        self.alg_combobox = ttk.Combobox(self.alg_frame, textvariable=self.algorithm)
        self.alg_combobox['values'] = ('AES', 'DES', 'RSA')
        self.alg_combobox.grid(row=0, column=0, padx=5, pady=5)
        self.alg_combobox.current(0)

        # Operation Selection Frame
        self.op_frame = ttk.LabelFrame(root, text="Operation")
        self.op_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        self.operation = tk.StringVar()
        self.op_combobox = ttk.Combobox(self.op_frame, textvariable=self.operation)
        self.op_combobox['values'] = ('Encrypt', 'Decrypt')
        self.op_combobox.grid(row=0, column=0, padx=5, pady=5)
        self.op_combobox.current(0)

        # Input/Output Frame
        self.io_frame = ttk.LabelFrame(root, text="Input/Output")
        self.io_frame.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        self.input_label = ttk.Label(self.io_frame, text="Input Text/File:")
        self.input_label.grid(row=0, column=0, padx=5, pady=5)
        self.input_entry = ttk.Entry(self.io_frame, width=40)
        self.input_entry.grid(row=0, column=1, padx=5, pady=5)
        self.input_button = ttk.Button(self.io_frame, text="Browse", command=self.browse_input)
        self.input_button.grid(row=0, column=2, padx=5, pady=5)

        self.output_label = ttk.Label(self.io_frame, text="Output File:")
        self.output_label.grid(row=1, column=0, padx=5, pady=5)
        self.output_entry = ttk.Entry(self.io_frame, width=40)
        self.output_entry.grid(row=1, column=1, padx=5, pady=5)
        self.output_button = ttk.Button(self.io_frame, text="Browse", command=self.browse_output)
        self.output_button.grid(row=1, column=2, padx=5, pady=5)

        self.key_label = ttk.Label(self.io_frame, text="Key File:")
        self.key_label.grid(row=2, column=0, padx=5, pady=5)
        self.key_entry = ttk.Entry(self.io_frame, width=40)
        self.key_entry.grid(row=2, column=1, padx=5, pady=5)
        self.key_button = ttk.Button(self.io_frame, text="Browse", command=self.browse_key)
        self.key_button.grid(row=2, column=2, padx=5, pady=5)

        # Action Button
        self.action_button = ttk.Button(root, text="Execute", command=self.execute)
        self.action_button.grid(row=4, column=0, padx=10, pady=10)

    def browse_input(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, file_path)

    def browse_output(self):
        file_path = filedialog.asksaveasfilename()
        if file_path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, file_path)

    def browse_key(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, file_path)

    def execute(self):
        username = self.username_entry.get()
        password_auth = self.password_entry.get()

        if not authenticate(username, password_auth):
            messagebox.showerror("Authentication Error", "Invalid username or password")
            log_error("Authentication failed")
            return

        algorithm = self.algorithm.get().lower()
        operation = self.operation.get().lower()
        input_path = self.input_entry.get()
        output_path = self.output_entry.get()
        key_path = self.key_entry.get()

        if not input_path:
            messagebox.showerror("Input Error", "Please provide input text or file")
            return

        if not output_path:
            messagebox.showerror("Output Error", "Please provide output file path")
            return

        try:
            input_data = read_file(input_path)

            if algorithm == 'aes':
                if operation == 'encrypt':
                    key = generate_aes_key()
                    nonce, ciphertext, tag = aes_encrypt(input_data, key)
                    write_file(output_path, f'{nonce.hex()}:{ciphertext.hex()}:{tag.hex()}')
                    write_binary_file(f'{output_path}.key', key)
                    messagebox.showinfo("Key Generated", f"AES Key has been generated and saved to {output_path}.key")
                elif operation == 'decrypt':
                    key = read_binary_file(key_path)
                    nonce, ciphertext, tag = [bytes.fromhex(x) for x in input_data.split(':')]
                    plaintext = aes_decrypt(nonce, ciphertext, tag, key)
                    write_file(output_path, plaintext)

            elif algorithm == 'des':
                if operation == 'encrypt':
                    key = generate_des_key()
                    nonce, ciphertext, tag = des_encrypt(input_data, key)
                    write_file(output_path, f'{nonce.hex()}:{ciphertext.hex()}:{tag.hex()}')
                    write_binary_file(f'{output_path}.key', key)
                    messagebox.showinfo("Key Generated", f"DES Key has been generated and saved to {output_path}.key")
                elif operation == 'decrypt':
                    key = read_binary_file(key_path)
                    nonce, ciphertext, tag = [bytes.fromhex(x) for x in input_data.split(':')]
                    plaintext = des_decrypt(nonce, ciphertext, tag, key)
                    write_file(output_path, plaintext)

            elif algorithm == 'rsa':
                if operation == 'encrypt':
                    private_key, public_key = generate_rsa_keys()
                    ciphertext = rsa_encrypt(input_data, RSA.import_key(public_key))
                    write_file(output_path, f'{public_key.decode()}::{ciphertext.hex()}')
                    write_binary_file(f'{output_path}.key', private_key)
                    messagebox.showinfo("Key Generated", f"RSA Private Key has been generated and saved to {output_path}.key")
                elif operation == 'decrypt':
                    private_key = RSA.import_key(read_binary_file(key_path))
                    public_key, ciphertext_hex = input_data.split('::')
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    plaintext = rsa_decrypt(ciphertext, private_key)
                    write_file(output_path, plaintext)

            log_info(f"{operation.capitalize()}ion with {algorithm.upper()} completed successfully.")
            messagebox.showinfo("Success", f"{operation.capitalize()}ion with {algorithm.upper()} completed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            log_error(f"An error occurred: {e}")

def main():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
