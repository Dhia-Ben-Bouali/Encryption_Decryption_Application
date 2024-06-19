from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

gen_p1 = b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
pwd = "thisisapassword"
key = PBKDF2(pwd, gen_p1, dkLen=32)

#---------------------------------------for image-----------------------------------------------

def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv, encrypted_data

def decrypt_data(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def write_encrypted_data_iv(encrypted_data, iv, filename):
    with open(filename, 'wb') as f:
        f.write(iv)
        f.write(encrypted_data)

def read_encrypted_data_iv(filename):
    with open(filename, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
    return encrypted_data, iv

def read_image(filename):
    with open(filename, 'rb') as f:
        return f.read()

def write_binary_data(data, filename):
    with open(filename, 'wb') as f:
        f.write(data)

def encrypt_image(filename, key):
    image_data = read_image(filename)
    iv, encrypted_image = encrypt_data(image_data, key)
    return iv, encrypted_image

def decrypt_image(iv, encrypted_image, key):
    decrypted_image_data = decrypt_data(encrypted_image, key, iv)
    return decrypted_image_data

#---------------------------------------End for image--------------------------------------------

#---------------------------------------Test image-----------------------------------------------

image_filename = 'img/imagetestencryption.jpg'
iv, encrypted_image = encrypt_image(image_filename, key)

encrypted_image_filename = 'EncryptedImage.bin'
write_encrypted_data_iv(encrypted_image, iv, encrypted_image_filename)

print("Chiffrement de l'image terminé et enregistré dans", encrypted_image_filename)


encrypted_image_data, read_iv = read_encrypted_data_iv(encrypted_image_filename)
decrypted_image_data = decrypt_image(read_iv, encrypted_image_data, key)

decrypted_image_filename = 'DecryptedImage.png'
write_binary_data(decrypted_image_data, decrypted_image_filename)

print("Déchiffrement de l'image terminé et enregistré dans", decrypted_image_filename)

#---------------------------------------End Test image----------------------------------------------------