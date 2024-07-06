import tkinter as tk
from tkinter import messagebox, ttk
import re
import time

# Function to check password strength
def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (min 8 characters).")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("No digits found.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("No lowercase letters found.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("No uppercase letters found.")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("No special characters found.")

    common_patterns = ["password", "1234", "qwerty"]
    if any(pattern in password.lower() for pattern in common_patterns):
        feedback.append("Contains common pattern.")

    return score, ", ".join(feedback)

# Function to analyze the password
def analyze_password():
    password = password_entry.get()
    score, feedback = check_password_strength(password)
    
    # Update the progress bar and label based on score
    progress_var.set(score * 20)
    result_label.config(text=f"Password Score: {score}")
    weakness_label.config(text=f"Weaknesses: {feedback}")

    suggest_passwords()

# Function to suggest passwords
def suggest_passwords():
    global suggested_passwords
    password = password_entry.get()
    suggested_passwords = [
        password + "1!",
        "Secure" + password,
        password.capitalize() + "@123"
    ]
    suggestion_label.config(text=f"Suggestions:")
    
    for widget in suggestion_frame.winfo_children():
        widget.destroy()
    
    password_var.set(suggested_passwords[0])
    for pwd in suggested_passwords:
        tk.Radiobutton(suggestion_frame, text=pwd, variable=password_var, value=pwd).pack(anchor='w')

# Function to save the password
def save_password(password):
    if password:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open("passwords.txt", "a") as file:
            file.write(f"{timestamp} - {password}\n")
        messagebox.showinfo("Success", "Password saved successfully.")
    else:
        messagebox.showwarning("Error", "No password to save.")

# Initialize the main window
root = tk.Tk()
root.title("Password Analyzer")
root.geometry("400x500")
root.resizable(False, False)

# Top section with title and instructions
top_frame = tk.Frame(root)
top_frame.pack(pady=10)

title_label = tk.Label(top_frame, text="Password Analyzer Tool", font=("Helvetica", 16))
title_label.pack()

instructions_label = tk.Label(top_frame, text="Enter a password below and click 'Analyze' to check its strength.")
instructions_label.pack()

# Middle section with password entry, analyze button, result display, and feedback
middle_frame = tk.Frame(root)
middle_frame.pack(pady=10)

password_entry = tk.Entry(middle_frame, show='*', width=30)
password_entry.pack(pady=10)

analyze_button = tk.Button(middle_frame, text="Analyze", command=analyze_password)
analyze_button.pack(pady=10)

result_label = tk.Label(middle_frame, text="", fg="blue")
result_label.pack(pady=10)

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(middle_frame, variable=progress_var, maximum=100)
progress_bar.pack(pady=10, fill='x')

weakness_label = tk.Label(middle_frame, text="", fg="red")
weakness_label.pack(pady=10)

# Bottom section with password suggestions, save button, and suggestion display
bottom_frame = tk.Frame(root)
bottom_frame.pack(pady=10)

suggestion_label = tk.Label(bottom_frame, text="", fg="green")
suggestion_label.pack(pady=10)

suggestion_frame = tk.Frame(bottom_frame)
suggestion_frame.pack(pady=10)

password_var = tk.StringVar()

choose_button = tk.Button(bottom_frame, text="Choose Password", command=lambda: save_password(password_var.get()))
choose_button.pack(pady=10)

# Run the main loop
root.mainloop()
