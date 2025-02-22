import os
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk
import sqlite3
import hashlib

# Database initialization and table creation
db_connection = sqlite3.connect("user_data.db")
db_cursor = db_connection.cursor()
db_cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    address TEXT NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                    )''')
db_connection.commit()

def show_option_frame():
    login_frame.pack_forget()
    register_frame.pack_forget()
    dashboard_frame.pack_forget()
    option_frame.pack()

def show_login_frame():
    option_frame.pack_forget()
    login_frame.pack()

def show_register_frame():
    option_frame.pack_forget()
    register_frame.pack()


def register_user():
    name = name_entry.get()
    address = address_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if not name or not address or not username or not password:
        messagebox.showerror("Error", "All fields are required.")
        return

    password = hashlib.sha256(password.encode()).hexdigest()  # Securely hash the password

    try:
        db_cursor.execute("INSERT INTO users (name, address, username, password) VALUES (?, ?, ?, ?)",
                          (name, address, username, password))
        db_connection.commit()
        messagebox.showinfo("Success", "Registration successful. You can now log in.")
        register_frame.pack_forget()  # Hide the registration frame
        show_login_frame()  # Show the login frame
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists. Please choose a different username.")


def login_user():
    username = login_username_entry.get()
    password = login_password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter both username and password.")
        return

    password = hashlib.sha256(password.encode()).hexdigest()  # Securely hash the password

    db_cursor.execute("SELECT id, username, password FROM users WHERE username = ? AND password = ?", (username, password))
    user_data = db_cursor.fetchone()

    if user_data:
        # Successfully logged in
        login_username_entry.delete(0, tk.END)
        login_password_entry.delete(0, tk.END)
        login_frame.pack_forget()  # Hide the login frame
        app.title(f"Distributed File System - Welcome, {username}!")
        show_dashboard_frame()  # Show the dashboard frame
    else:
        messagebox.showerror("Login Failed", "Invalid username or password.")

# Create a function to show the dashboard frame
def show_dashboard_frame():
    dashboard_frame.pack()

def logout_user():
    dashboard_frame.pack_forget()
    show_option_frame()
    app.title("Distributed File System")
    login_username_entry.delete(0, tk.END)
    login_password_entry.delete(0, tk.END)

def upload_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_name = os.path.basename(file_path)
        destination_path = os.path.join("shared_files", file_name)
        try:
            # Copy the file to the shared_files directory
            with open(file_path, 'rb') as source_file:
                with open(destination_path, 'wb') as destination_file:
                    destination_file.write(source_file.read())
            status_label.config(text=f"File '{file_name}' uploaded successfully.")
            update_list_box()
        except Exception as e:
            status_label.config(text=f"Error uploading file: {str(e)}")

def update_list_box():
    list_box.delete(0, tk.END)  # Clear the list box
    shared_files = os.listdir("shared_files")
    for file_name in shared_files:
        list_box.insert(tk.END, file_name)
Aaditya
Aaditya Pokhrel
# Create a button to upload files
upload_button = ttk.Button(dashboard_frame, text="Upload File", command=upload_file)
upload_button.pack(pady=10)

# Create a button to list files
list_files_button = ttk.Button(dashboard_frame, text="List Files", command=update_list_box)
list_files_button.pack(pady=5)

# Create a button to download files
download_button = ttk.Button(dashboard_frame, text="Download File", command=download_file)
download_button.pack(pady=5)

# Create a button to delete files
delete_button = ttk.Button(dashboard_frame, text="Delete File", command=delete_file)
delete_button.pack(pady=5)

# Create a button to logout
logout_button = ttk.Button(dashboard_frame, text="Logout", command=logout_user)
logout_button.pack(pady=5)

# Create a button to exit the application
exit_button = ttk.Button(dashboard_frame, text="Exit", command=exit_app)
exit_button.pack(pady=5)

# Create a list box to display the uploaded files
list_box = tk.Listbox(dashboard_frame, width=50, bg='black', fg='white')  # Black background with white text
list_box.pack(pady=5)

# Create a label to show the status of the file upload
status_label = ttk.Label(dashboard_frame, text="", style="Red.TLabel", foreground='white')  # White text on red background
status_label.pack()

# Start with the option frame
show_option_frame()

# Start the tkinter event loop
app.mainloop()