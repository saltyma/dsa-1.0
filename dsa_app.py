import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk
import sqlite3
import hashlib
import base64
import os
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# Connect to SQLite database
conn = sqlite3.connect('users.db')
c = conn.cursor()

def hash_password(password):
    salt = base64.b64encode(os.urandom(16)).decode('utf-8')
    hashed_password = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, hashed_password

def verify_password(stored_password, salt, provided_password):
    hashed_password = hashlib.sha256((salt + provided_password).encode()).hexdigest()
    return hashed_password == stored_password

def register_user(username, password):
    salt, hashed_password = hash_password(password)
    try:
        c.execute("INSERT INTO users (username, salt, password) VALUES (?, ?, ?)", (username, salt, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login_user(username, password):
    c.execute("SELECT id, salt, password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result and verify_password(result[2], result[1], password):
        return result[0]  # Return user_id
    else:
        return None

def generate_keys():
    private_key = dsa.generate_private_key(key_size=1024)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_image(image, private_key):
    data = image.tobytes()
    signature = private_key.sign(data, hashes.SHA256())
    return signature

def verify_signature(image, signature, public_key):
    data = image.tobytes()
    try:
        public_key.verify(signature, data, Prehashed(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

class DigitalArtSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Art Signature")
        self.root.configure(bg='#2e2e2e')
        self.current_user_id = None
        self.current_username = None
        self.artwork_image = None
        self.signed_artwork = None
        self.signature = None
        self.private_key = None
        self.public_key = None

        self.create_auth_widgets()

    def create_auth_widgets(self):
        self.clear_widgets()

        self.username_label = tk.Label(self.root, text="Username:", bg='#2e2e2e', fg='white')
        self.username_label.grid(row=0, column=0, pady=5, padx=5)
        
        self.username_entry = tk.Entry(self.root, bg='#3e3e3e', fg='white')
        self.username_entry.grid(row=0, column=1, pady=5, padx=5)

        self.password_label = tk.Label(self.root, text="Password:", bg='#2e2e2e', fg='white')
        self.password_label.grid(row=1, column=0, pady=5, padx=5)

        self.password_entry = tk.Entry(self.root, show="*", bg='#3e3e3e', fg='white')
        self.password_entry.grid(row=1, column=1, pady=5, padx=5)

        self.login_button = tk.Button(self.root, text="Login", command=self.login, bg='#007acc', fg='white')
        self.login_button.grid(row=2, column=0, pady=5, padx=5)

        self.register_button = tk.Button(self.root, text="Register", command=self.register, bg='#007acc', fg='white')
        self.register_button.grid(row=2, column=1, pady=5, padx=5)

    def create_main_widgets(self):
        self.clear_widgets()

        self.greeting_label = tk.Label(self.root, text=f"Hello, {self.current_username}", bg='#2e2e2e', fg='white')
        self.greeting_label.grid(row=0, column=0, pady=5, padx=5, sticky='w')

        self.logout_button = tk.Button(self.root, text="Logout", command=self.logout, bg='#007acc', fg='white')
        self.logout_button.grid(row=0, column=1, pady=5, padx=5, sticky='e')

        self.artwork_list = tk.Listbox(self.root, bg='#3e3e3e', fg='white')
        self.artwork_list.grid(row=1, column=0, columnspan=2, pady=5, padx=5, sticky='nsew')
        self.artwork_list.bind('<<ListboxSelect>>', self.display_artwork)

        self.upload_button = tk.Button(self.root, text="Upload Artwork", command=self.upload_artwork, bg='#007acc', fg='white')
        self.upload_button.grid(row=2, column=0, pady=5, padx=5, sticky='ew')

        self.sign_button = tk.Button(self.root, text="Sign Artwork", command=self.sign_artwork, bg='#007acc', fg='white')
        self.sign_button.grid(row=2, column=1, pady=5, padx=5, sticky='ew')

        self.export_button = tk.Button(self.root, text="Export Signature", command=self.export_signature, bg='#007acc', fg='white')
        self.export_button.grid(row=3, column=0, pady=5, padx=5, sticky='ew')

        self.delete_button = tk.Button(self.root, text="Delete Artwork", command=self.delete_artwork, bg='#007acc', fg='white')
        self.delete_button.grid(row=3, column=1, pady=5, padx=5, sticky='ew')

        self.load_artworks()

    def clear_widgets(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def load_artworks(self):
        self.artwork_list.delete(0, tk.END)
        c.execute("SELECT id, unique_id FROM artworks WHERE user_id = ?", (self.current_user_id,))
        for artwork in c.fetchall():
            self.artwork_list.insert(tk.END, f"Artwork ID: {artwork[1]}")

    def display_artwork(self, event):
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            unique_id = self.artwork_list.get(index).split(": ")[1]
            c.execute("SELECT artwork, signature FROM artworks WHERE unique_id = ?", (unique_id,))
            artwork, signature = c.fetchone()
            self.artwork_image = Image.open(artwork)
            self.artwork_image.thumbnail((400, 300))
            self.artwork_photo = ImageTk.PhotoImage(self.artwork_image)
            self.canvas = tk.Canvas(self.root, width=400, height=300, bg='#2e2e2e')
            self.canvas.grid(row=4, column=0, columnspan=2, pady=5, padx=5)
            self.canvas.create_image(200, 150, image=self.artwork_photo)
            self.signature_text = tk.Text(self.root, height=4, width=40, bg='#3e3e3e', fg='white')
            self.signature_text.grid(row=5, column=0, columnspan=2, pady=5, padx=5)
            self.signature_text.insert(tk.END, signature)
            self.signature_text.config(state=tk.DISABLED)

    def upload_artwork(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.artwork_image = Image.open(file_path)
            self.artwork_image.thumbnail((400, 300))
            self.artwork_photo = ImageTk.PhotoImage(self.artwork_image)
            self.canvas = tk.Canvas(self.root, width=400, height=300, bg='#2e2e2e')
            self.canvas.grid(row=4, column=0, columnspan=2, pady=5, padx=5)
            self.canvas.create_image(200, 150, image=self.artwork_photo)

    def sign_artwork(self):
        if not self.artwork_image:
            messagebox.showerror("Error", "No artwork uploaded.")
            return

        self.private_key, self.public_key = generate_keys()
        self.signature = sign_image(self.artwork_image, self.private_key)

        with open(self.artwork_image.filename, 'rb') as file:
            artwork_data = file.read()

        unique_id = str(uuid4())

        c.execute("INSERT INTO artworks (user_id, unique_id, artwork, signature) VALUES (?, ?, ?, ?)",
                  (self.current_user_id, unique_id, self.artwork_image.filename, base64.b64encode(self.signature).decode('utf-8')))
        conn.commit()
        self.load_artworks()
        messagebox.showinfo("Success", "Artwork signed successfully!")

    def delete_artwork(self):
        selection = self.artwork_list.curselection()
        if selection:
            index = selection[0]
            unique_id = self.artwork_list.get(index).split(": ")[1]
            c.execute("DELETE FROM artworks WHERE unique_id = ?", (unique_id,))
            conn.commit()
            self.load_artworks()
            self.canvas.delete("all")
            self.signature_text.config(state=tk.NORMAL)
            self.signature_text.delete("1.0", tk.END)
            self.signature_text.config(state=tk.DISABLED)
            messagebox.showinfo("Success", "Artwork deleted successfully!")

    def export_signature(self):
        selection = self.artwork_list.curselection()
        if selection:
            index = selection[0]
            unique_id = self.artwork_list.get(index).split(": ")[1]
            c.execute("SELECT signature FROM artworks WHERE unique_id = ?", (unique_id,))
            signature = c.fetchone()[0]
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(signature)
                messagebox.showinfo("Success", "Signature exported successfully!")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_id = login_user(username, password)
        if user_id:
            self.current_user_id = user_id
            self.current_username = username
            self.create_main_widgets()
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if register_user(username, password):
            messagebox.showinfo("Success", "Registration successful. Please login.")
        else:
            messagebox.showerror("Error", "Username already exists.")

    def logout(self):
        self.current_user_id = None
        self.current_username = None
        self.create_auth_widgets()

if __name__ == "__main__":
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  username TEXT UNIQUE, 
                  salt TEXT, 
                  password TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS artworks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  user_id INTEGER, 
                  unique_id TEXT, 
                  artwork TEXT, 
                  signature TEXT, 
                  FOREIGN KEY (user_id) REFERENCES users(id))''')

    root = tk.Tk()
    app = DigitalArtSignatureApp(root)
    root.mainloop()
