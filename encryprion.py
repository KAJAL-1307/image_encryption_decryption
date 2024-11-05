import os
import string
import base64 
from Crypto import Random
from Crypto.Cipher import AES
import hashlib

block_size = 16
pad_len=0

def sha256(key):
	sha = hashlib.sha256()
	sha.update(key.encode('utf-8'))
	return sha.digest()

def pad(plain,block):
	pad_len = len(plain) % block
	return plain+((block-pad_len)*chr(block-pad_len)).encode('ascii')

def unpad(plain,block):
	
	return plain[0:-(block_size-pad_len)]

def encrypt(plain,key):
	plain = pad(plain,block_size)
	iv = Random.new().read(block_size)
	cipher = AES.new(key,AES.MODE_CBC,iv)
	final_cipher = cipher.encrypt(plain)
	print("encrypted")
	return base64.b64encode(iv+final_cipher)

def decrypt(ciphertext,key):
	ciphertext = base64.b64decode(ciphertext)
	iv = ciphertext[:16]
	cipher = AES.new(key,AES.MODE_CBC,iv)
	plaintext = cipher.decrypt(ciphertext[16:])
	print("decrypted")
	return unpad(plaintext,block_size) 


n=int(input("1.encrypt\n2.decrypt"))
if(n==1):
      file = input('Enter the name of the file ')
      key = input('Enter a key ')
      with open("key_hash.txt", 'wb') as key_file:
            key_file.write(sha256(key))
      fp = open(file,'rb')
      base64_file = base64.b64encode(fp.read())
      
      key = sha256(key)
      enc = encrypt(base64_file,key)
      fp1 = open("encryptedfile.png",'wb')
      fp1.write(enc)
	  
      fp1.close()
      fp.close()
elif(n==2):
	key_input = input("Enter the key to unlock: ")
	key_hash = sha256(key_input)
	
	if os.path.exists("key_hash.txt"):# Load the saved key hash
		with open("key_hash.txt", 'rb') as key_file:
			saved_key_hash = key_file.read()
			print("Key is correct. Proceeding with decryption...")
	with open("encryptedfile.png", 'rb') as enc_file:
		enc = enc_file.read()		

	if(key_hash == saved_key_hash):
				dec = decrypt(enc,key_hash)
				fp2 = open('decryptedfile.png','wb')
				fp2.write(base64.b64decode(dec))
				fp2.close()
