from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad

#semetric_key = get_random_bytes(32)
#print(semetric_key)

print("--------------------------KEY Generation--------------------------")

gen_p1= b',E\x1a4\xf9e\xc0\x8f\x89\xc7\xc3J\xd3f\xa4\xe2E\xfa0\xfa\xcf.\xbf\xefb3m\xfe\x00h\rE'
pwd = "thisisapassword"
key= PBKDF2(pwd,gen_p1,dkLen=32)
print(key)

print("--------------------------MESSAGE--------------------------")

message = input("Veuillez entrer votre message : ")

message_bytes = message.encode('utf-8')

print("--------------------------Encypted Message--------------------------")

cipher = AES.new(key, AES.MODE_CBC)
encryptedmessage = cipher.encrypt(pad(message_bytes, AES.block_size))
print(encryptedmessage)

print("--------------------------Export Bin--------------------------")

with open ('Encryted.bin', 'wb') as f:
    f.write(cipher.iv)
    f.write(encryptedmessage)
print("Export Bin Done")

print("--------------------------Import Bin--------------------------")

with open ('Encryted.bin', 'rb' ) as f:
    iv= f.read(16)
    MesageToDecrypt = f.read()
print("Import Done")

print("--------------------------Decypted Message--------------------------")

cipher = AES.new(key , AES.MODE_CBC , iv=iv)
Decryptedmessage = unpad(cipher.decrypt(MesageToDecrypt), AES.block_size)
print(Decryptedmessage)
DecryptedMessageStr = Decryptedmessage.decode('utf-8')

print("--------------------------Export txt--------------------------")

with open('DecryptedMessage.txt', 'w') as file:
    file.write(DecryptedMessageStr)
print("Export Text Done")

print("--------------------------Export Key--------------------------")

with open('Key.bin' , 'wb') as file:
    file.write(key)
print("Export Key Done")