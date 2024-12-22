import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image, ImageTk, ImageFilter
import numpy as np
import os
import hashlib
import base64

class ModernSteganographyApp:
    def __init__(self, master):
        self.master = master
        master.title("StegoCrypt Pro")
        master.geometry("1000x700")
        master.configure(bg='#1A2634')  # Slightly darker background

        # Custom theme configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self._create_custom_styles()

        # Main container with gradient background
        self.main_container = tk.Frame(master, bg='#1A2634')
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Create notebook with modern styling
        self.notebook = ttk.Notebook(self.main_container, style='Modern.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Encode frame
        self._create_encode_frame()

        # Decode frame
        self._create_decode_frame()

    def _create_custom_styles(self):
        # Custom color palette
        bg_dark = '#1A2634'
        bg_medium = '#2C3E50'
        bg_light = '#3498DB'
        text_color = '#ECF0F1'
        accent_color = '#2980B9'

        # Custom style for rounded buttons
        self.style.element_create("roundedbtn", "from", "clam")
        self.style.layout("Rounded.TButton", [
            ('Button.padding', {'children':
                [('Button.label', {'sticky': ''})],
                'sticky': 'nswe'})])
        
        # Notebook style
        self.style.configure('Modern.TNotebook', background=bg_dark)
        self.style.configure('Modern.TNotebook.Tab', 
                             background=bg_medium, 
                             foreground=text_color, 
                             padding=[10, 5],
                             font=('Segoe UI', 12, 'bold'))
        self.style.map('Modern.TNotebook.Tab', 
                       background=[('selected', bg_light)],
                       foreground=[('selected', 'white')])

        # Rounded Button styles
        self.style.configure('Rounded.TButton', 
                             background=accent_color, 
                             foreground='white', 
                             font=('Segoe UI', 11, 'bold'),
                             padding=10,
                             borderwidth=0,
                             relief='flat')
        self.style.map('Rounded.TButton', 
                       background=[
                           ('active', '#34495E'), 
                           ('pressed', '#2C3E50')
                       ])

        # Entry and Label styles
        self.style.configure('Modern.TEntry', 
                             background='white', 
                             foreground='black', 
                             font=('Segoe UI', 11),
                             borderwidth=1,
                             relief='solid')
        self.style.configure('Modern.TLabel', 
                             background=bg_dark, 
                             foreground=text_color, 
                             font=('Segoe UI', 12, 'bold'))

        # Frame style for consistent background
        self.style.configure('Modern.TFrame', background=bg_dark)

    def _create_encode_frame(self):
        encode_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(encode_frame, text="Encode")

        # Image selection section
        image_section = ttk.Frame(encode_frame, style='Modern.TFrame')
        image_section.pack(fill='x', pady=15, padx=20)

        ttk.Label(image_section, text="Select Image", style='Modern.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        self.image_path_encode = tk.StringVar()
        image_path_entry = ttk.Entry(image_section, 
                                     textvariable=self.image_path_encode, 
                                     width=50, 
                                     style='Modern.TEntry')
        image_path_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=(0, 10))

        select_image_btn = ttk.Button(image_section, 
                                      text="Browse", 
                                      style='Rounded.TButton', 
                                      command=self.select_image_for_encode)
        select_image_btn.pack(side=tk.LEFT)

        # Message input section
        message_section = ttk.Frame(encode_frame, style='Modern.TFrame')
        message_section.pack(fill='x', pady=15, padx=20)

        ttk.Label(message_section, text="Message", style='Modern.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        self.message_entry = ttk.Entry(message_section, 
                                       width=50, 
                                       style='Modern.TEntry')
        self.message_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=(0, 10))

        # Optional password protection
        password_section = ttk.Frame(encode_frame, style='Modern.TFrame')
        password_section.pack(fill='x', pady=15, padx=20)

        ttk.Label(password_section, text="Password (Optional)", style='Modern.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        self.password_entry = ttk.Entry(password_section, 
                                        width=50, 
                                        show='*', 
                                        style='Modern.TEntry')
        self.password_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=(0, 10))

        # Encode button
        encode_btn = ttk.Button(encode_frame, 
                                text="Hide Message", 
                                style='Rounded.TButton', 
                                command=self.encode_message)
        encode_btn.pack(pady=20)

    def _create_decode_frame(self):
        decode_frame = ttk.Frame(self.notebook, style='Modern.TFrame')
        self.notebook.add(decode_frame, text="Decode")

        # Image selection section
        image_section = ttk.Frame(decode_frame, style='Modern.TFrame')
        image_section.pack(fill='x', pady=15, padx=20)

        ttk.Label(image_section, text="Select Image", style='Modern.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        self.image_path_decode = tk.StringVar()
        image_path_entry = ttk.Entry(image_section, 
                                     textvariable=self.image_path_decode, 
                                     width=50, 
                                     style='Modern.TEntry')
        image_path_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=(0, 10))

        select_image_btn = ttk.Button(image_section, 
                                      text="Browse", 
                                      style='Rounded.TButton', 
                                      command=self.select_image_for_decode)
        select_image_btn.pack(side=tk.LEFT)

        # Password section
        password_section = ttk.Frame(decode_frame, style='Modern.TFrame')
        password_section.pack(fill='x', pady=15, padx=20)

        ttk.Label(password_section, text="Password", style='Modern.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        self.decode_password_entry = ttk.Entry(password_section, 
                                               width=50, 
                                               show='*', 
                                               style='Modern.TEntry')
        self.decode_password_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=(0, 10))

        # Decode button
        decode_btn = ttk.Button(decode_frame, 
                                text="Extract Message", 
                                style='Rounded.TButton', 
                                command=self.decode_message)
        decode_btn.pack(pady=20)

        # Decoded message display
        message_display_section = ttk.Frame(decode_frame, style='Modern.TFrame')
        message_display_section.pack(fill='x', pady=15, padx=20)

        ttk.Label(message_display_section, text="Hidden Message", style='Modern.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        self.decoded_message = tk.StringVar()
        decoded_message_label = ttk.Label(message_display_section, 
                                          textvariable=self.decoded_message, 
                                          style='Modern.TLabel', 
                                          foreground='#3498DB')
        decoded_message_label.pack(side=tk.LEFT, expand=True)

    def select_image_for_encode(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.bmp *.jpg"), 
                       ("PNG files", "*.png"),
                       ("BMP files", "*.bmp")],
            title="Select Image to Encode"
        )
        if filename:
            self.image_path_encode.set(filename)

    def encode_message(self):
        image_path = self.image_path_encode.get()
        message = self.message_entry.get()
        password = self.password_entry.get()

        if not image_path or not message:
            messagebox.showerror("Error", "Please select an image and enter a message")
            return

        try:
            # Optional password encryption
            if password:
                salt = os.urandom(16)
                key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                message = base64.b64encode(message.encode()).decode()

            img = Image.open(image_path)
            img_array = np.array(img)

            binary_message = ''.join(format(ord(char), '08b') for char in message)
            binary_message += '1111111'  # End marker

            flattened_img = img_array.flatten()
            for i, bit in enumerate(binary_message):
                flattened_img[i] = (flattened_img[i] & 0xFE) | int(bit)

            encoded_img_array = flattened_img.reshape(img_array.shape)
            encoded_img = Image.fromarray(encoded_img_array.astype('uint8'))

            # Optional image filter for added complexity
            encoded_img = encoded_img.filter(ImageFilter.GaussianBlur(radius=0.5))

            # Save the encoded image
            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
            if output_path:
                encoded_img.save(output_path)
                messagebox.showinfo("Success", "Message encoded and saved successfully.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def select_image_for_decode(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.bmp *.jpg"), 
                       ("PNG files", "*.png"),
                       ("BMP files", "*.bmp")],
            title="Select Image to Decode"
        )
        if filename:
            self.image_path_decode.set(filename)

    def decode_message(self):
        image_path = self.image_path_decode.get()
        password = self.decode_password_entry.get()

        if not image_path:
            messagebox.showerror("Error", "Please select an image")
            return

        try:
            img = Image.open(image_path)
            img_array = np.array(img).flatten()

            binary_message = ''
            for pixel in img_array:
                binary_message += str(pixel & 1)

            # Split binary message into bytes and convert to characters
            bytes_list = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
            decoded_chars = [chr(int(byte, 2)) for byte in bytes_list]
            hidden_message = ''.join(decoded_chars).split('1111111')[0]

            # Decrypt if password is provided
            if password:
                hidden_message = base64.b64decode(hidden_message.encode()).decode()

            self.decoded_message.set(hidden_message)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernSteganographyApp(root)
    root.mainloop()
