import re
from zxcvbn import zxcvbn
from tkinter import Tk, Label, Entry, StringVar, Button, messagebox
from passwordgenerator import pwgenerator
import pyperclip

# Dummy password history for demonstration
password_history = ["OldPassword1!", "PreviousPass2@", "AnotherOldPass3#"]

def check_password_strength(password):
    result = zxcvbn(password)
    score = result['score']
    feedback = result['feedback']
    
    # Check additional criteria for password validity
    length_check = len(password) >= 8
    uppercase_check = bool(re.search(r"[A-Z]", password))
    lowercase_check = bool(re.search(r"[a-z]", password))
    number_check = bool(re.search(r"[0-9]", password))
    special_char_check = bool(re.search(r"[\W_]", password))
    
    if not all([length_check, uppercase_check, lowercase_check, number_check, special_char_check]):
        score = 0
        feedback['suggestions'].append("Password must be at least 8 characters long.")
        feedback['suggestions'].append("Password must contain uppercase letters, lowercase letters, numbers, and special characters.")

    # Determine password strength based on zxcvbn score
    if score == 0:
        strength = "Very Weak"
    elif score == 1:
        strength = "Weak"
    elif score == 2:
        strength is "Moderate"
    elif score == 3:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    # Detailed feedback
    suggestions = feedback['suggestions']
    warning = feedback['warning']

    return strength, suggestions, warning

def generate_strong_password():
    # Generate a strong password
    strong_password = pwgenerator(length=16)
    return strong_password

def on_password_entry(*args):
    password = password_var.get()
    strength, suggestions, warning = check_password_strength(password)
    
    strength_var.set(f"Password Strength: {strength}")
    
    suggestions_text = "Suggestions:\n" + "\n".join(suggestions)
    warning_text = f"Warning: {warning}" if warning else ""
    feedback_var.set(f"{suggestions_text}\n{warning_text}")
    
    if strength in ["Very Weak", "Weak"]:
        strong_password = generate_strong_password()
        suggestion_label.config(text=f"Suggested Strong Password: {strong_password}")

    # Password history check
    if password in password_history:
        history_var.set("This password has been used before. Choose a different password.")
    else:
        history_var.set("")

def copy_to_clipboard():
    strong_password = suggestion_label.cget("text").replace("Suggested Strong Password: ", "")
    if strong_password:
        pyperclip.copy(strong_password)
        messagebox.showinfo("Password Copied", "The suggested strong password has been copied to clipboard.")

def display_password_policy():
    policy = """
    Password Policy:
    1. Minimum length: 8 characters
    2. Must include lowercase letters
    3. Must include uppercase letters
    4. Must include numbers
    5. Must include special characters
    6. Should not match previous passwords
    """
    messagebox.showinfo("Password Policy", policy)

# Setting up the GUI using tkinter
root = Tk()
root.title("Password Strength Checker")

password_var = StringVar()
password_var.trace("w", on_password_entry)
strength_var = StringVar()
feedback_var = StringVar()
history_var = StringVar()

Label(root, text="Enter Password:").grid(row=0, column=0, padx=10, pady=10)
Entry(root, textvariable=password_var, show='*').grid(row=0, column=1, padx=10, pady=10)
Label(root, textvariable=strength_var).grid(row=1, columnspan=2, padx=10, pady=10)
Label(root, textvariable=feedback_var, justify='left').grid(row=2, columnspan=2, padx=10, pady=10)
Label(root, textvariable=history_var, fg='red').grid(row=3, columnspan=2, padx=10, pady=10)
suggestion_label = Label(root, text="", justify='left', fg='blue')
suggestion_label.grid(row=4, columnspan=2, padx=10, pady=10)

Button(root, text="Copy to Clipboard", command=copy_to_clipboard).grid(row=5, column=0, pady=10)
Button(root, text="Show Policy", command=display_password_policy).grid(row=5, column=1, pady=10)
Button(root, text="Exit", command=root.quit).grid(row=6, columnspan=2, pady=10)

root.mainloop()
