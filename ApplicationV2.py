import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image, ImageTk

class Application(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Application de Chiffrement AES")
        self.geometry("600x400")

        # Style pour le titre
        self.title_font = ("Arial", 16, "bold")
        self.title_color = "#157eb3"
        self.entry_font = ("Arial", 12)
        self.entry_bg = "#f0f0f0"
        self.entry_fg = "#333333"

        self.current_page = None  

        # Barre de navigation
        self.frame_navigation = tk.Frame(self)
        self.frame_navigation.pack(pady=0, padx=10, anchor='n') 

        self.link_page_texte = tk.Label(self.frame_navigation, text="Texte", fg="#000000", cursor="hand2", font=("Arial", 12,"bold"))
        self.link_page_texte.pack(side=tk.LEFT, padx=10)
        self.link_page_texte.bind("<Button-1>", lambda event: self.show_page_texte())

        self.link_page_image = tk.Label(self.frame_navigation, text="Image", fg="#000000", cursor="hand2", font=("Arial", 12,"bold"))
        self.link_page_image.pack(side=tk.LEFT, padx=10)
        self.link_page_image.bind("<Button-1>", lambda event: self.show_page_image())

        # Page Texte (Chiffrement)
        self.page_texte = tk.Frame(self)

        self.label_texte = tk.Label(self.page_texte, text="Chiffrement AES - Texte", font=self.title_font, fg=self.title_color)
        self.label_texte.pack(pady=20)

        self.label_message = tk.Label(self.page_texte, text="Entrez votre message :", font=self.entry_font, fg=self.entry_fg)
        self.label_message.pack()

        self.entry_message = tk.Entry(self.page_texte, width=50, font=self.entry_font, bg=self.entry_bg, fg=self.entry_fg)
        self.entry_message.pack(pady=10)

        self.frame_boutons_texte = tk.Frame(self.page_texte)
        self.frame_boutons_texte.pack(pady=20)

        self.btn_chiffrer_texte = tk.Button(self.frame_boutons_texte, text="Chiffrer le message", command=self.chiffrer_message_texte)
        self.btn_chiffrer_texte.grid(row=0, column=0, padx=10)

        self.btn_dechiffrer_texte = tk.Button(self.frame_boutons_texte, text="Déchiffrer le message", command=self.dechiffrer_message_texte)
        self.btn_dechiffrer_texte.grid(row=0, column=1, padx=10)

        self.btn_export_key_texte = tk.Button(self.frame_boutons_texte, text="Exporter la clé", command=self.exporter_cle_texte)
        self.btn_export_key_texte.grid(row=0, column=2, padx=10)

        self.style_buttons_texte()

        # Page Image
        self.page_image = tk.Frame(self)

        self.label_image = tk.Label(self.page_image, text="Chiffrement AES - Image", font=self.title_font, fg=self.title_color)
        self.label_image.pack(pady=20)

        self.btn_choisir_image = tk.Button(self.page_image, text="Choisir une image", command=self.choisir_image)
        self.btn_choisir_image.pack(pady=10)

        self.image_label = tk.Label(self.page_image)
        self.image_label.pack()

        self.frame_boutons_image = tk.Frame(self.page_image)
        self.frame_boutons_image.pack(pady=20)

        self.btn_chiffrer_image = tk.Button(self.frame_boutons_image, text="Chiffrer l'image", command=self.chiffrer_image)
        self.btn_chiffrer_image.grid(row=0, column=0, padx=10)

        self.btn_dechiffrer_image = tk.Button(self.frame_boutons_image, text="Déchiffrer l'image", command=self.dechiffrer_image)
        self.btn_dechiffrer_image.grid(row=0, column=1, padx=10)

        self.btn_export_key_image = tk.Button(self.frame_boutons_image, text="Exporter la clé", command=self.exporter_cle_image)
        self.btn_export_key_image.grid(row=0, column=2, padx=10)

        self.style_buttons_image()

        # Initialisation avec la page de texte
        self.show_page_texte()

    def style_buttons_texte(self):
        button_font = ("Arial", 12, "bold")
        button_bg = "#157eb3"
        button_fg = "white"

        self.btn_chiffrer_texte.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)
        self.btn_dechiffrer_texte.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)
        self.btn_export_key_texte.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)

    def style_buttons_image(self):
        button_font = ("Arial", 12, "bold")
        button_bg = "#157eb3"
        button_fg = "white"

        self.btn_chiffrer_image.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)
        self.btn_dechiffrer_image.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)
        self.btn_export_key_image.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)

    def show_page_texte(self):
        if self.current_page:
            self.current_page.pack_forget()  # Cacher la page actuelle

        self.page_texte.pack()
        self.current_page = self.page_texte

    def show_page_image(self):
        if self.current_page:
            self.current_page.pack_forget()  # Cacher la page actuelle

        self.page_image.pack()
        self.current_page = self.page_image

    def chiffrer_message_texte(self):
        message = self.entry_message.get()

        if not message:
            messagebox.showerror("Erreur", "Veuillez entrer un message à chiffrer.")
            return

        gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
        pwd = "thisisapassword"
        key = PBKDF2(pwd, gen_p1, dkLen=32)

        message_bytes = message.encode('utf-8')

        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_message = cipher.encrypt(pad(message_bytes, AES.block_size))

        with open('Encryted_texte.bin', 'wb') as f:
            f.write(cipher.iv)
            f.write(encrypted_message)

        messagebox.showinfo("Succès", "Le message a été chiffré avec succès.")

    def dechiffrer_message_texte(self):
        try:
            with open('Encryted_texte.bin', 'rb') as f:
                iv = f.read(16)
                message_to_decrypt = f.read()

            gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
            pwd = "thisisapassword"
            key = PBKDF2(pwd, gen_p1, dkLen=32)

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_message = unpad(cipher.decrypt(message_to_decrypt), AES.block_size)
            decrypted_message_str = decrypted_message.decode('utf-8')

            with open('DecryptedMessage_texte.txt', 'w') as file:
                file.write(decrypted_message_str)

            messagebox.showinfo("Succès", "Le message a été déchiffré avec succès et exporté dans DecryptedMessage_texte.txt.")

        except FileNotFoundError:
            messagebox.showerror("Erreur", "Fichier Encryted_texte.bin introuvable. Veuillez chiffrer un message d'abord.")

    def exporter_cle_texte(self):
        gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
        pwd = "thisisapassword"
        key = PBKDF2(pwd, gen_p1, dkLen=32)

        with open('Key_texte.bin', 'wb') as file:
            file.write(key)

        messagebox.showinfo("Succès", "La clé a été exportée avec succès dans Key_texte.bin.")

    def choisir_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.png;*.jpeg")])

        if file_path:
            self.image = Image.open(file_path)
            self.image = self.image.resize((300, 300), Image.ANTIALIAS)
            self.photo_image = ImageTk.PhotoImage(self.image)

            self.image_label.config(image=self.photo_image)
            self.image_label.image = self.photo_image  

    def chiffrer_image(self):
        if not hasattr(self, 'image'):
            messagebox.showerror("Erreur", "Veuillez d'abord choisir une image.")
            return

        gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
        pwd = "thisisapassword"
        key = PBKDF2(pwd, gen_p1, dkLen=32)

        image_bytes = self.image.tobytes()

        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_image = cipher.encrypt(pad(image_bytes, AES.block_size))

        with open('Encryted_image.bin', 'wb') as f:
            f.write(cipher.iv)
            f.write(encrypted_image)

        messagebox.showinfo("Succès", "L'image a été chiffrée avec succès.")

    def dechiffrer_image(self):
        try:
            with open('Encryted_image.bin', 'rb') as f:
                iv = f.read(16)
                image_to_decrypt = f.read()

            gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
            pwd = "thisisapassword"
            key = PBKDF2(pwd, gen_p1, dkLen=32)

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_image = unpad(cipher.decrypt(image_to_decrypt), AES.block_size)

            img = Image.frombytes('RGB', (300, 300), decrypted_image)
            img.show()

        except FileNotFoundError:
            messagebox.showerror("Erreur", "Fichier Encryted_image.bin introuvable. Veuillez chiffrer une image d'abord.")

    def exporter_cle_image(self):
        gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
        pwd = "thisisapassword"
        key = PBKDF2(pwd, gen_p1, dkLen=32)

        with open('Key_image.bin', 'wb') as file:
            file.write(key)

        messagebox.showinfo("Succès", "La clé a été exportée avec succès dans Key_image.bin.")

if __name__ == "__main__":
    app = Application()
    app.mainloop()
