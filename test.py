#!/usr/bin/env python3

import base64
import Crypto.Cipher.AES as AES
import Crypto.Random as RND
import hashlib as hl
import os
import random as rnd
import string
import tkinter as tk
import tkinter.messagebox as mb

'''
	Create a new directory (folder) in an easily accessible place on your computer.
	Place this file in that location.
	On the first run, 'keys.csv' and 'hash' will be created automatically.
	'hash' stores the SHA-512 of your passphrase and a hint for the passphrase.
	'keys.csv' stores the your passwords after they have been encrypted with AES256.
	Do not, under any circumstances, modify 'hash' or 'keys.csv' by hand!
'''

################################################################################

# the font that labels in a window use
titlefont = 'Noto 15 bold'
subtitlefont = 'Noto 10 bold'

################################################################################

def genpass(n):
	'''
	Generate a random password of the specified length.
	There will be more English letters in the password than special characters.

	Args:
		n: the length of the random password to be generated

	Returns:
		password made of random English letters and special characters
	'''

	letter = string.ascii_letters
	digit = string.digits
	punct = string.punctuation
	return ''.join(rnd.choice(2 * letter + digit + punct) for _ in range(n))

################################################################################

def show_pass(entry_name):
	'''
	Toggle how the contents of the argument (an Entry) are displayed.
	Change the display mode from asterisks to normal and vice versa.

	Args:
		entry_name: name of entry whose contents have to be censored or displayed

	Returns:
		None
	'''

	if entry_name['show'] == '*':
		entry_name['show'] = ''
	else:
		entry_name['show'] = '*'

################################################################################

def encryptAES(plaintext, AES_key):
	'''
		Encrypt a given string using AES256.
		Convert a plaintext string to base64 string ciphertext.
		Ciphertext is encrypted data appended to initialization vector.
		Ciphertext is a base64 string.
	'''

	initialization_vector = RND.new().read(AES.block_size);
	encryption_suite = AES.new(AES_key, AES.MODE_CFB, initialization_vector)
	composite = initialization_vector + encryption_suite.encrypt(plaintext.encode())
	ciphertext = base64.b64encode(composite).decode()
	return ciphertext

def decryptAES(ciphertext, AES_key):
	'''
		Decrypt a given string using AES256.
		Convert a base64 string ciphertext to a plaintext string.
		Separate the initialization vector in the ciphertext.
		Decrypt to get plaintext bytes, but return it as a string.
	'''

	ciphertext = base64.b64decode(ciphertext.encode())
	initialization_vector = ciphertext[: AES.block_size]
	decryption_suite = AES.new(AES_key, AES.MODE_CFB, initialization_vector)
	plaintext = decryption_suite.decrypt(ciphertext[AES.block_size :]).decode()
	return plaintext

################################################################################

class CreateTooltip:
	'''
		Display a hint when the mouse hovers above a widget.
		This will probably avoid having to include instructions for using this application.
		Tix is not used because it seems out of date.
	'''

	def __init__(self, widget, text = 'widget'):
		self.widget = widget
		self.text = text
		widget.bind('<Enter>', self.enter)
		widget.bind('<Leave>', self.leave)

	########################################

	def enter(self, event):
		'''
			When the mouse pointer hovers over a widget, display the tip.
		'''

		# locate the tip box
		x, y, cx, cy = self.widget.bbox('insert')
		x += self.widget.winfo_rootx() + 25
		y += self.widget.winfo_rooty() + 30

		# the tip box is a tk.Toplevel with its title bar removed
		self.tw = tk.Toplevel(self.widget)
		self.tw.wm_overrideredirect(True)
		self.tw.wm_geometry('+%d+%d' % (x, y))
		tk.Label(self.tw, text = self.text).pack()

	########################################

	def leave(self, event):
		'''
			When the mouse pointer leaves the widget, close the hint.
		'''

		if self.tw:
			self.tw.destroy()

################################################################################

class BaseWindowClass:
	'''
		Base class which will be inherited to display tkinter windows.
	'''

	def __init__(self, parent):
		self.parent = parent
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)

	########################################

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

################################################################################

class Login(BaseWindowClass):
	'''
		Take the master password of the user as input.
		Compute its SHA-512 and compare it with the stored SHA-512.
		If they are different, show an error message and allow retrying.
		Otherwise, the user is logged in and can use the application.
	'''

	def __init__(self, parent):
		super().__init__(parent)
		parent.title('Log In')
		parent.bind('<Return>', self.press_enter)

		# header
		head = tk.Label(parent, text = 'Enter Passphrase', font = titlefont)
		head.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# keyboard instruction
		inst = tk.Label(parent, text = 'Press \'Esc\' to quit the application.')
		inst.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		# accept user input
		phrase_entry = tk.Entry(parent, show = '*')
		phrase_entry.grid(row = 2, column = 1, padx = 30, pady = 15)
		phrase_entry.focus()

		# toggle passphrase view
		show_button = tk.Button(parent, text = 'Passphrase', font = subtitlefont, command = lambda : show_pass(phrase_entry))
		show_button.grid(row = 2, column = 0, padx = 30, pady = 15)
		CreateTooltip(show_button, 'Show or hide passphrase')

		# display hint
		hint_button = tk.Button(parent, text = 'Passphrase Hint', height = 2, width = 20, command = self.view_hint)
		hint_button.grid(row = 3, columnspan = 2, padx = 30, pady = (30, 15))

		# check if password is correct and proceed
		self.submit = tk.Button(parent, text = 'Log In', height = 2, width = 20, command = lambda : self.validate_phrase(phrase_entry.get()))
		self.submit.grid(row = 4, columnspan = 2, padx = 30, pady = (15, 30))

	########################################

	def close_button(self, event = None):
		raise SystemExit(0)

	########################################

	def press_enter(self, event = None):
		'''
			Find out
		'''
		widget = self.parent.focus_get()
		if isinstance(widget, tk.Button):
			widget.invoke()
		else:
			self.submit.invoke()

	########################################

	def view_hint(self):
		with open('hash') as hash_file:
			hint = hash_file.readlines()[1].strip()
			mb.showinfo('Passphrase Hint', hint)

	########################################

	# 'Log In' button event
	def validate_phrase(self, phrase):

		# compare the string stored in the file 'hash' with the SHA-512 of 'phrase'
		phrase_hash = hl.sha512(phrase.encode()).hexdigest()
		with open('hash') as hash_file:
			expected_hash = hash_file.readline().strip()
		if phrase_hash != expected_hash:
			mb.showerror('Wrong Passphrase', 'The passphrase entered is wrong.')
			return

		# if the passphrase was correct, close this window and set 'self.AES_key'
		# which will be used as the encryption / decryption key for AES
		self.parent.destroy()
		self.AES_key = hl.sha256(phrase.encode()).digest()


if __name__ == '__main__':
	# root = tk.Tk()
	# root_BaseClass = BaseClass(root)
	# root.mainloop()

	# x = 'srbsedfvvgedvgdvfoemxpuifbhasch,widj'
	# k = hl.sha256('avfegbsdvge'.encode()).digest()
	# y = encryptAES(x, k)
	# z = decryptAES(y, k)
	# print(x)
	# print(y)
	# print(z)
	# print(k)

	cop = tk.Tk()
	cop_Login = Login(cop)
	cop.mainloop()

	print('boobs')
