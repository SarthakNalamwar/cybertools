import tkinter as tk
from tkinter import filedialog, messagebox
from encryption import encrypt_image, decrypt_image
from image_handler import load_image, save_image, display_image

def encrypt_action():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    if not file_path:
        return
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    try:
        image_data = load_image(file_path)
        encrypted_data = encrypt_image(image_data, password)
        save_image(encrypted_data, file_path + ".enc")
        messagebox.showinfo("Success", "Image encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    if not file_path:
        return
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    try:
        encrypted_data = load_image(file_path)
        decrypted_data = decrypt_image(encrypted_data, password)
        save_image(decrypted_data, file_path.replace(".enc", ".dec.png"))
        display_image(decrypted_data)
        messagebox.showinfo("Success", "Image decrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Setup UI
root = tk.Tk()
root.title("Image Encryption Tool")

frame = tk.Frame(root)
frame.pack(pady=10)

password_label = tk.Label(frame, text="Password:")
password_label.pack(side=tk.LEFT, padx=5)

password_entry = tk.Entry(frame, show="*")
password_entry.pack(side=tk.LEFT, padx=5)

encrypt_button = tk.Button(root, text="Encrypt Image", command=encrypt_action)
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt Image", command=decrypt_action)
decrypt_button.pack(pady=5)

root.mainloop()
