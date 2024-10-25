import customtkinter as ctk
import sqlite3
import bcrypt
from tkinter import messagebox

# Database Setup
conn = sqlite3.connect("password_manager.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS form_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    roll TEXT,
    number TEXT
)
""")
conn.commit()


# Functions for user management
def register_user(username, password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        messagebox.showinfo("Success", "User registered successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")


def login_user(username, password):
    cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        return user[0]
    messagebox.showerror("Error", "Incorrect username or password.")
    return None


# Main Application
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.user_id = None
        ctk.set_appearance_mode("dark")
        root.geometry("800x600")  # Increased window size
        root.title("KeyNest - by Al Kayes Rifat")
        self.login_screen()

    def add_footer(self, frame):
        footer_label = ctk.CTkLabel(frame, text="Developed by Al Kayes Rifat", font=("Helvetica", 14, "bold"))
        footer_label.pack(side="bottom", pady=20)

    def login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        login_frame = ctk.CTkFrame(self.root, width=500, height=400, corner_radius=15)
        login_frame.pack(pady=20)

        ctk.CTkLabel(login_frame, text="Login", font=("Helvetica", 24)).pack(pady=20)
        self.username_entry = ctk.CTkEntry(login_frame, placeholder_text="Username", width=300)
        self.username_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(login_frame, placeholder_text="Password", show="*", width=300)
        self.password_entry.pack(pady=10)

        ctk.CTkButton(login_frame, text="Login", command=self.login, width=200, height=40).pack(pady=10)
        ctk.CTkButton(login_frame, text="Register", command=self.register_screen, width=200, height=40).pack(pady=5)

        self.add_footer(login_frame)

    def register_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        register_frame = ctk.CTkFrame(self.root, width=500, height=400, corner_radius=15)
        register_frame.pack(pady=20)

        ctk.CTkLabel(register_frame, text="Register", font=("Helvetica", 24)).pack(pady=20)
        self.username_entry = ctk.CTkEntry(register_frame, placeholder_text="Username", width=300)
        self.username_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(register_frame, placeholder_text="Password", show="*", width=300)
        self.password_entry.pack(pady=10)

        ctk.CTkButton(register_frame, text="Register", command=self.register, width=200, height=40).pack(pady=10)
        ctk.CTkButton(register_frame, text="Back to Login", command=self.login_screen, width=200, height=40).pack(pady=5)

        self.add_footer(register_frame)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            register_user(username, password)
            self.login_screen()
        else:
            messagebox.showwarning("Input Error", "Please fill out all fields")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_id = login_user(username, password)
        if user_id:
            self.user_id = user_id
            self.password_manager_screen()

    def password_manager_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        manager_frame = ctk.CTkFrame(self.root, width=500, height=400, corner_radius=15)
        manager_frame.pack(pady=20)

        ctk.CTkLabel(manager_frame, text="Password Manager", font=("Helvetica", 24)).pack(pady=20)

        ctk.CTkButton(manager_frame, text="Add Password", command=self.add_password_screen, width=200, height=40).pack(pady=10)
        ctk.CTkButton(manager_frame, text="View Passwords", command=self.view_passwords_screen, width=200, height=40).pack(pady=10)
        ctk.CTkButton(manager_frame, text="Logout", command=self.login_screen, width=200, height=40).pack(pady=10)

        self.add_footer(manager_frame)

    def add_password_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        add_frame = ctk.CTkFrame(self.root, width=500, height=400, corner_radius=15)
        add_frame.pack(pady=20)

        ctk.CTkLabel(add_frame, text="Add New Password", font=("Helvetica", 24)).pack(pady=20)

        self.site_entry = ctk.CTkEntry(add_frame, placeholder_text="Site", width=300)
        self.site_entry.pack(pady=5)

        self.site_username_entry = ctk.CTkEntry(add_frame, placeholder_text="Username", width=300)
        self.site_username_entry.pack(pady=5)

        self.site_password_entry = ctk.CTkEntry(add_frame, placeholder_text="Password", show="*", width=300)
        self.site_password_entry.pack(pady=5)

        ctk.CTkButton(add_frame, text="Save Password", command=self.save_password, width=200, height=40).pack(pady=10)
        ctk.CTkButton(add_frame, text="Back", command=self.password_manager_screen, width=200, height=40).pack(pady=5)

        self.add_footer(add_frame)

    def save_password(self):
        site = self.site_entry.get()
        site_username = self.site_username_entry.get()
        site_password = self.site_password_entry.get()
        if site and site_username and site_password:
            cursor.execute("INSERT INTO passwords (user_id, site, username, password) VALUES (?, ?, ?, ?)",
                           (self.user_id, site, site_username, site_password))
            conn.commit()
            messagebox.showinfo("Success", "Password saved successfully!")
            self.password_manager_screen()
        else:
            messagebox.showwarning("Input Error", "Please fill out all fields")

    def view_passwords_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        view_frame = ctk.CTkFrame(self.root, width=500, height=400, corner_radius=15)
        view_frame.pack(pady=20)

        ctk.CTkLabel(view_frame, text="Your Saved Passwords", font=("Helvetica", 24)).pack(pady=20)

        cursor.execute("SELECT id, site, username, password FROM passwords WHERE user_id = ?", (self.user_id,))
        passwords = cursor.fetchall()

        for password_id, site, username, password in passwords:
            password_frame = ctk.CTkFrame(view_frame, corner_radius=10, fg_color="#2c2c2e")
            password_frame.pack(fill="x", pady=5, padx=10)

            ctk.CTkLabel(password_frame, text=f"{site}", font=("Helvetica", 18)).pack(side="left", padx=10)
            ctk.CTkLabel(password_frame, text=f"{username} - {password}", font=("Helvetica", 15)).pack(side="left", padx=5)

            delete_button = ctk.CTkButton(password_frame, text="Delete", command=lambda id=password_id: self.delete_password(id), width=50, height=30)
            delete_button.pack(side="right", padx=10)

        ctk.CTkButton(view_frame, text="Back", command=self.password_manager_screen, width=200, height=40).pack(pady=10)

        self.add_footer(view_frame)

    def delete_password(self, password_id):
        cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
        conn.commit()
        messagebox.showinfo("Success", "Password deleted successfully!")
        self.view_passwords_screen()


if __name__ == "__main__":
    root = ctk.CTk()
    app = PasswordManagerApp(root)
    root.mainloop()
