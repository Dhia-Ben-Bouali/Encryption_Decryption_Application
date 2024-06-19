import tkinter as tk
from tkinter import messagebox
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Application(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Application de Chiffrement AES")
        self.geometry("600x300")

        # Style pour le titre
        self.title_font = ("Arial", 16, "bold")
        self.title_color = "#157eb3"
        self.entry_font = ("Arial", 12)
        self.entry_bg = "#f0f0f0"
        self.entry_fg = "#333333"

        self.current_page = None  

        self.frame_navigation = tk.Frame(self)
        self.frame_navigation.pack(pady=0, padx=10, anchor='n') 

        self.link_page_chiffrement = tk.Label(self.frame_navigation, text="Texte", fg="#000000", cursor="hand2", font=("Arial", 12,"bold"))
        self.link_page_chiffrement.pack(side=tk.LEFT, padx=10)
        self.link_page_chiffrement.bind("<Button-1>", lambda event: self.show_page_chiffrement())

        self.link_page_navigation = tk.Label(self.frame_navigation, text="Image", fg="#000000", cursor="hand2", font=("Arial", 12,"bold"))
        self.link_page_navigation.pack(side=tk.LEFT, padx=10)
        self.link_page_navigation.bind("<Button-1>", lambda event: self.show_page_navigation())

        #Page Chiffrement
        self.page_chiffrement = tk.Frame(self)

        self.label = tk.Label(self.page_chiffrement, text="Chiffrement AES", font=self.title_font, fg=self.title_color)
        self.label.pack(pady=20)

        self.label_message = tk.Label(self.page_chiffrement, text="Entrez votre message :", font=self.entry_font, fg=self.entry_fg)
        self.label_message.pack()

        self.entry_message = tk.Entry(self.page_chiffrement, width=50, font=self.entry_font, bg=self.entry_bg, fg=self.entry_fg)
        self.entry_message.pack(pady=10)

        self.frame_boutons_chiffrement = tk.Frame(self.page_chiffrement)
        self.frame_boutons_chiffrement.pack(pady=20)

        self.btn_chiffrer = tk.Button(self.frame_boutons_chiffrement, text="Chiffrer le message", command=self.chiffrer_message)
        self.btn_chiffrer.grid(row=0, column=0, padx=10)

        self.btn_dechiffrer = tk.Button(self.frame_boutons_chiffrement, text="Déchiffrer le message", command=self.dechiffrer_message)
        self.btn_dechiffrer.grid(row=0, column=1, padx=10)

        self.btn_export_key = tk.Button(self.frame_boutons_chiffrement, text="Exporter la clé", command=self.exporter_cle)
        self.btn_export_key.grid(row=0, column=2, padx=10)

        self.style_buttons()

        # Page image 
        self.page_navigation = tk.Frame(self)

        # Initialisation avec la page de chiffrement
        self.show_page_chiffrement()

    def style_buttons(self):
        button_font = ("Arial", 12, "bold")
        button_bg = "#157eb3"
        button_fg = "white"

        self.btn_chiffrer.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)
        self.btn_dechiffrer.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)
        self.btn_export_key.configure(font=button_font, bg=button_bg, fg=button_fg, padx=10, pady=5)

    def show_page_chiffrement(self):
        if self.current_page:
            self.current_page.pack_forget()  # Cacher la page actuelle

        self.page_chiffrement.pack()
        self.current_page = self.page_chiffrement

    def show_page_navigation(self):
        if self.current_page:
            self.current_page.pack_forget()  # Cacher la page actuelle

        self.page_navigation.pack()
        self.current_page = self.page_navigation

    def chiffrer_message(self):
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

        with open('Encryted.bin', 'wb') as f:
            f.write(cipher.iv)
            f.write(encrypted_message)

        messagebox.showinfo("Succès", "Le message a été chiffré avec succès.")

    def dechiffrer_message(self):
        try:
            with open('Encryted.bin', 'rb') as f:
                iv = f.read(16)
                message_to_decrypt = f.read()

            gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
            pwd = "thisisapassword"
            key = PBKDF2(pwd, gen_p1, dkLen=32)

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_message = unpad(cipher.decrypt(message_to_decrypt), AES.block_size)
            decrypted_message_str = decrypted_message.decode('utf-8')

            with open('DecryptedMessage.txt', 'w') as file:
                file.write(decrypted_message_str)

            messagebox.showinfo("Succès", "Le message a été déchiffré avec succès et exporté dans DecryptedMessage.txt.")

        except FileNotFoundError:
            messagebox.showerror("Erreur", "Fichier Encryted.bin introuvable. Veuillez chiffrer un message d'abord.")

    def exporter_cle(self):
        gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
        pwd = "thisisapassword"
        key = PBKDF2(pwd, gen_p1, dkLen=32)

        with open('Key.bin', 'wb') as file:
            file.write(key)

        messagebox.showinfo("Succès", "La clé a été exportée avec succès dans Key.bin.")

if __name__ == "__main__":
    app = Application()
    app.mainloop()
