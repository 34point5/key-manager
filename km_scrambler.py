#!/usr/bin/env python3

import base64
import Crypto.Cipher.AES as AES
import Crypto.Random as Random

################################################################################

def encrypt(plaintext, key):
	'''
	Encrypt a given string using AES256.
	Before encrypting, plaintext string is converted to bytes.
	After encrypting, bytes are converted back to string.

	Args:
		plaintext: string to be encrypted
		key: stream of bytes (256-bit encryption key)

	Returns:
		base64-encoded ciphertext (encrypted plaintext) string
	'''

	initialization_vector = Random.new().read(AES.block_size)
	encryption_suite = AES.new(key, AES.MODE_CFB, initialization_vector)
	composite = initialization_vector + encryption_suite.encrypt(plaintext.encode())
	ciphertext = base64.b64encode(composite).decode()
	return ciphertext

################################################################################

def decrypt(ciphertext, key):
	'''
	Decrypt a given string using AES256.
	Before decrypting, ciphertext string is converted to bytes.
	After decrypting, bytes are converted back to string.

	Args:
		ciphertext: base64-encoded string to be decrypted
		key: stream of bytes (256-bit encryption key) (same as encryption key above)

	Returns:
		plaintext (decrypted ciphertext) string
	'''

	ciphertext = base64.b64decode(ciphertext.encode())
	initialization_vector = ciphertext[: AES.block_size]
	decryption_suite = AES.new(key, AES.MODE_CFB, initialization_vector)
	plaintext = decryption_suite.decrypt(ciphertext[AES.block_size :]).decode()
	return plaintext
