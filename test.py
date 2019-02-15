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

# Create a new directory (folder) in an easily accessible place on your computer.
# Place this file in that location.
# On the first run, 'keys.csv' and 'hash' will be created automatically.
# 'hash' stores the SHA-512 of your passphrase and a hint for the passphrase.
# 'keys.csv' stores the your passwords after they have been encrypted with AES256.
# Do not, under any circumstances, modify 'hash' or 'keys.csv' by hand!

################################################################################

# some settings
titlefont = 'Noto 15 bold' # window head label font
subtitlefont = 'Noto 10 bold' # font used by label associated with an Entry
passlength = 18 # length of the random password generated
phraselength = 0 # minimum passphrase length required while changing it

################################################################################

def genpass(n):
	'''
	Generate a random password of the specified length.
	There will be more English letters in the password than special characters.

	Args:
		n: the integer length of the random password to be generated

	Returns:
		password string made of random English letters and special characters
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
		entry_name: tk.Entry object whose contents have to be censored or displayed

	Returns:
		None
	'''

	if entry_name['show'] == '*':
		entry_name['show'] = ''
	else:
		entry_name['show'] = '*'

################################################################################

def encryptAES(plaintext, key):
	'''
	Encrypt a given string using AES256.
	Before encrypting, plaintext string is converted to bytes.
	After encrypting, bytes are converted back to string.

	Args:
		plaintext: string to be encrypted
		key: stream of bytes (256-bit encryption key)

	Returns:
		base64-encoded ciphertext (encrypted version of plaintext) string
	'''

	initialization_vector = RND.new().read(AES.block_size);
	encryption_suite = AES.new(key, AES.MODE_CFB, initialization_vector)
	composite = initialization_vector + encryption_suite.encrypt(plaintext.encode())
	ciphertext = base64.b64encode(composite).decode()
	return ciphertext

################################################################################

def decryptAES(ciphertext, key):
	'''
	Decrypt a given string using AES256.
	Before decrypting, ciphertext string is converted to bytes.
	After decrypting, bytes are converted back to string.

	Args:
		ciphertext: base64-encoded string to be decrypted
		AES_key: stream of bytes (256-bit encryption key) (same as encryption key above)

	Returns:
		plaintext (decrypted version of plaintext) string
	'''

	ciphertext = base64.b64decode(ciphertext.encode())
	initialization_vector = ciphertext[: AES.block_size]
	decryption_suite = AES.new(key, AES.MODE_CFB, initialization_vector)
	plaintext = decryption_suite.decrypt(ciphertext[AES.block_size :]).decode()
	return plaintext

################################################################################

class CreateTooltip:
	'''
	Display a hint when the mouse hovers over a widget.
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

		Args:
			self: class object
			event: GUI event

		Returns:
			None
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

		Args:
			self: class object
			event: GUI event

		Returns:
			None
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
		parent.bind('<Return>', self.press_enter)

	########################################

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	########################################

	def press_enter(self, event = None):
		'''
		When the user presses 'Return', decide what action to perform.
		If the widget in focus is a button, invoke its action.
		Else, invoke the action of the 'submit' button.
		BaseWindowClass does not have a 'submit' button.
		But the classes inheriting it will all have a 'submit' button.

		Args:
			self: class object
			event: GUI event

		Returns:
			None
		'''

		widget = self.parent.focus_get()
		if isinstance(widget, tk.Button):
			widget.invoke()
		else:
			self.submit.invoke()

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

		# header
		head_label = tk.Label(parent, text = 'Enter Passphrase', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to quit the application.')
		inst_label.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		# passphrase prompt entry
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

	def view_hint(self):
		'''
		Display the hint for the passphrase.
		The hint is the second line of the 'hash' file.
		Display it as it is.

		Args:
			self: class object

		Returns:
			None
		'''

		with open('hash') as hash_file:
			hint = hash_file.readlines()[1].strip()
			mb.showinfo('Passphrase Hint', hint)

	########################################

	def validate_phrase(self, phrase):
		'''
		Compare the SHA-512 of the entered passphrase with the stored value.
		If they are the same, set the SHA-256 of the passphrase as the AES256 key.
		SHA-256 is conveniently 256 bits long, which is the key length of AES256.

		Args:
			self: class object
			phrase: passphrase string

		Returns:
			None
		'''

		# compare the string stored in the file 'hash' with the SHA-512 of 'phrase'
		phrase_hash = hl.sha512(phrase.encode()).hexdigest()
		with open('hash') as hash_file:
			expected_hash = hash_file.readline().strip()
		if phrase_hash != expected_hash:
			mb.showerror('Wrong Passphrase', 'The passphrase entered is wrong.')
			return

		# if the passphrase was correct, close this window and set 'self.AES_key'
		# which will be used as the encryption / decryption key for AES
		self.parent.quit()
		self.parent.destroy()
		self.key = hl.sha256(phrase.encode()).digest()

################################################################################

class Choose(BaseWindowClass):
	'''
	What does the user want to do?
	Add a password.
	Delete a password.
	Change a password.
	View a password.
	Change the passphrase.
	'''

	def __init__(self, parent, key):
		super().__init__(parent)
		parent.title('Password Manager Main Menu')
		self.key = key

		# header
		head_label = tk.Label(parent, text = 'What would you like to do?', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to quit the application.')
		inst_label.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		# add password
		add_button = tk.Button(parent, text = 'Add a Password', height = 2, width = 20, command = lambda : add_password(self))
		add_button.grid(row = 2, column = 0, padx = 30, pady = 15)

		# delete button
		del_button = tk.Button(parent, text = 'Delete a Password', height = 2, width = 20, command = lambda : delete_password(self))
		del_button.grid(row = 2, column = 1, padx = 30, pady = 15)

		# change button
		chg_button = tk.Button(parent, text = 'Change a Password', height = 2, width = 20, command = lambda : change_password(self))
		chg_button.grid(row = 3, column = 0, padx = 30, pady = 15)

		# view button
		view_button = tk.Button(parent, text = 'View a Password', height = 2, width = 20, command = lambda : view_password(self))
		view_button.grid(row = 3, column = 1, padx = 30, pady = 15)

		# change passphrase button
		chp_button = tk.Button(parent, text = 'Change Passphrase', height = 2, width = 20, command = lambda : change_passphrase(self))
		chp_button.grid(row = 4, columnspan = 2, padx = 30, pady = (15, 30))

	########################################

	def close_button(self, event = None):
		raise SystemExit(0)

	########################################

	def press_enter(self, event = None):
		'''
		When the user presses 'Return', decide what action to perform.
		Override the inherited method because this window does not have a 'submit' button.
		Because this window does not have a 'submit' button.
		Hence, the inherited method will not work.
		If any of the buttons are in focus, perform the action.
		Else, do nothing.

		Args:
			self: class object
			event: GUI event

		Returns:
			None
		'''

		widget = self.parent.focus_get()
		if isinstance(widget, tk.Button):
			widget.invoke()

################################################################################

def add_password(choose_window):
	'''
	Wrapper function to instantiate the AddPassword class.

	Args:
		choose_window: the Choose object whose window has to be hidden before displaying a new window

	Returns:
		None
	'''

	# hide the option choosing window
	choose_window.parent.withdraw()

	adder = tk.Toplevel(choose_window.parent)
	AddPassword(adder, choose_window.key)
	adder.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

################################################################################

class AddPassword(BaseWindowClass):
	'''
	Create a window to add a new password. A line will be added to 'keys.csv' file.
	The password will be encrypted and stored. The other credentials are stored raw.
	Hence, no credentials (other than the password) should contain a comma.
	'''

	def __init__(self, parent, key):
		super().__init__(parent)
		parent.title('Add a Password')
		self.key = key
		self.plvar = tk.StringVar(value = genpass(passlength)) # for 'refresh_button'
		self.accvar = tk.StringVar() # for 'acc_entry'
		self.uidvar = tk.StringVar() # for 'uid_entry'
		self.namevar = tk.StringVar() # for 'name_entry'
		self.pwvar = tk.StringVar() # for 'pw_entry'
		self.cpvar = tk.StringVar() # for 'cp_entry'

		# header
		head_label = tk.Label(parent, text = 'Enter Credentials', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		# account prompt label
		acc_label = tk.Label(parent, text = 'Account', font = subtitlefont)
		acc_label.grid(row = 2, column = 0, padx = 30, pady = 15)

		# user ID prompt label
		uid_label = tk.Label(parent, text = 'User ID (e.g. email)', font = subtitlefont)
		uid_label.grid(row = 3, column = 0, padx = 30, pady = 15)

		# user name prompt label
		name_label = tk.Label(parent, text = 'User Name', font = subtitlefont)
		name_label.grid(row = 4, column = 0, padx = 30, pady = 15)

		# account prompt entry
		acc_entry = tk.Entry(parent, textvariable = self.accvar)
		acc_entry.grid(row = 2, column = 1, padx = 30, pady = 15)
		acc_entry.focus()

		# user ID prompt entry
		uid_entry = tk.Entry(parent, textvariable = self.uidvar)
		uid_entry.grid(row = 3, column = 1, padx = 30, pady = 15)

		# user name prompt entry
		name_entry = tk.Entry(parent, textvariable = self.namevar)
		name_entry.grid(row = 4, column = 1, padx = 30, pady = 15)

		# password prompt entry
		pw_entry = tk.Entry(parent, textvariable = self.pwvar, show = '*')
		pw_entry.grid(row = 6, column = 1, padx = 30, pady = 15)

		# confirm password prompt entry
		cp_entry = tk.Entry(parent, textvariable = self.cpvar, show = '*')
		cp_entry.grid(row = 7, column = 1, padx = 30, pady = 15)

		# add the password to the file
		self.submit = tk.Button(parent, text = 'Add', height = 2, width = 20, command = lambda : self.validate_pw(acc_entry.get(), uid_entry.get(), name_entry.get(), pw_entry.get(), cp_entry.get()))
		self.submit.grid(row = 8, columnspan = 2, padx = 30, pady = 30)

		# auto-fill password entries
		autofill_button = tk.Button(parent, text = 'Suggested Password', font = subtitlefont, command = self.set_passwords)
		autofill_button.grid(row = 5, column = 0, padx = 30, pady = 15)
		CreateTooltip(autofill_button, 'Auto-fill the password entries\nbelow with the suggested password')

		# refresh suggested password
		refresh_button = tk.Button(parent, textvariable = self.plvar, command = lambda : self.plvar.set(genpass(passlength)), width = 30)
		refresh_button.grid(row = 5, column = 1, padx = 30, pady = 15)
		CreateTooltip(refresh_button, 'Re-generate suggested password')

		# toggle password view
		pass_button = tk.Button(parent, text = 'Password', font = subtitlefont, command = lambda : show_pass(pw_entry))
		pass_button.grid(row = 6, column = 0, padx = 30, pady = 15)
		CreateTooltip(pass_button, 'Show or hide password')

		# toggle confirm password view
		cpass_button = tk.Button(parent, text = 'Confirm Password', font = subtitlefont, command = lambda : show_pass(cp_entry))
		cpass_button.grid(row = 7, column = 0, padx = 30, pady = 15)
		CreateTooltip(cpass_button, 'Show or hide password')

	########################################

	def set_passwords(self):
		'''
		Set the entries next to 'Password' and 'Confirm Password' to the sugggested password.

		Args:
			self: class object

		Returns:
			None
		'''

		self.pwvar.set(self.plvar.get())
		self.cpvar.set(self.plvar.get())

	########################################

	def validate_pw(self, *credentials):
		'''
		Check whether the credentials provided by the user are appropriate.
		The account, user ID, user name and password entries must not be empty.
		Both password entries mst have the same string.
		There must be no comma in the account, user ID and user name entries.

		Args:
			self: class object
			credentials: list of credential strings the user entered

		Returns:
			None
		'''

		# check if any field is empty
		if '' in credentials:
			mb.showerror('Empty Input', 'One or more fields are still empty. Fill all of them to proceed.')
			return

		# check if any of the first three credentials contain a comma
		if ',' in ''.join(credentials[: 3]):
			mb.showerror('Invalid Input', 'The \'Account\', \'User ID\' and \'User Name\' fields must not contain commas.')
			return

		# rename credentials for convenience
		acc, uid, name, pw, cp = credentials

		# compare passwords
		if pw != cp:
			mb.showerror('Password Mismatch', 'The \'Password\' and \'Confirm Password\' fields do not match.')
			return

		# confirm and add password
		response = mb.askyesno('Confirmation', 'Add this password?', icon = 'warning')
		if response == False:
			return
		with open('keys.csv', 'a') as password_file:
			print('{},{},{},{}'.format(acc, uid, name, encryptAES(pw, self.key)), file = password_file)
			mb.showinfo('Password Added', 'Password for {} was added successfully.'.format(name))

		self.parent.quit()
		self.parent.destroy()

################################################################################

def change_passphrase(choose_window):
	'''
	Wrapper function to instantiate the ChangePassphrase class.

	Args:
		choose_window: the Choose object whose window has to be hidden before displaying a new window

	Returns:
		None
	'''

	# hide the option choosing window
	choose_window.parent.withdraw()

	updater = tk.Toplevel(choose_window.parent)
	updater_ChangePassphrase = ChangePassphrase(updater, choose_window.key)
	updater.mainloop()
	choose_window.key = updater_ChangePassphrase.key # set the updated AES_key

	# unhide the option choosing window
	choose_window.parent.deiconify()

################################################################################

class ChangePassphrase(BaseWindowClass):
	'''
	Change the passphrase that must be entered to log in.
	The passwords have been encrypted using 'key', which is obtained from the passphrase.
	Hence, if the passphrase is changed, 'key' will also change.
	Therefore, after the passphrase is changed, decrypt the stored passwords using the old value of 'key'.
	Then re-encrypt them using the new value of 'key'.
	This new value of 'key' must be sent back to the main menu.
	It is done using 'self.key' attribute.
	'''

	def __init__(self, parent, key):
		super().__init__(parent)
		parent.title('Change Passphrase')
		self.key = key

		# header
		head_label = tk.Label(parent, text = 'Enter new Passphrase', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# sub-header
		subhead_label = tk.Label(parent, text = 'Use a long easy-to-remember passphrase.\nAvoid a short random one. Include special characters!')
		subhead_label.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 2, columnspan = 2, padx = 30, pady = (0, 30))

		# passphrase hint prompt label
		hint_label = tk.Label(parent, text = 'Passphrase Hint', font = subtitlefont)
		hint_label.grid(row = 5, column = 0, padx = 30, pady = 15)

		# passphrase prompt entry
		pp_entry = tk.Entry(parent, show = '*')
		pp_entry.grid(row = 3, column = 1, padx = 30, pady = 15)
		pp_entry.focus()

		# confirm passphrase prompt entry
		cp_entry = tk.Entry(parent, show = '*')
		cp_entry.grid(row = 4, column = 1, padx = 30, pady = 15)

		# passphrase hint prompt entry
		hint_entry = tk.Entry(parent)
		hint_entry.grid(row = 5, column = 1, padx = 30, pady = 15)

		# change the passphrase
		self.submit = tk.Button(parent, text = 'Change', height = 2, width = 20, command = lambda : self.update_phrase(pp_entry.get(), cp_entry.get(), hint_entry.get()))
		self.submit.grid(row = 6, columnspan = 2, padx = 30, pady = 30)

		# toggle passphrase view
		pp_button = tk.Button(parent, text = 'New Passphrase', font = subtitlefont, command = lambda : show_pass(pp_entry))
		pp_button.grid(row = 3, column = 0, padx = 30, pady = 15)
		CreateTooltip(pp_button, 'Show or hide passphrase')

		# toggle confirm passphrase view
		cp_button = tk.Button(parent, text = 'Confirm Passphrase', font = subtitlefont, command = lambda : show_pass(cp_entry))
		cp_button.grid(row = 4, column = 0, padx = 30, pady = 15)
		CreateTooltip(cp_button, 'Show or hide passphrase')

	########################################

	def update_phrase(self, pp, cp, hint):
		'''
		Change the passphrase used for logins.
		Calculate the SHA-512 of the new passphrase. Overwrite it onto 'hash'.
		A passphrase hint is necessary to set a new passphrase.

		Args:
			self: class object
			pp: new passphrase string
			cp: confirm passphrase string
			hint: passphrase hint string

		Returns:
			None
		'''

		# check passphrase length
		if len(pp) < phraselength:
			mb.showerror('Invalid Passphrase', 'The passphrase should be at least {} characters long.'.format(phraselength))
			return

		# compare passphrases
		if pp != cp:
			mb.showerror('Passphrase Mismatch', 'The \'Passphrase\' and \'Confirm Passphrase\' fields do not match.')
			return

		# passphrase hint is necessary
		if hint == '':
			mb.showerror('Hint Required', 'You must provide a hint for the new passphrase.')
			return

		# confirm
		response = mb.askyesno('Confirmation', 'Change Passphrase?', icon = 'warning')
		if response == False:
			return

		# write the SHA-512 of the new passphrase to a new file
		with open('.hash', 'w') as hash_file:
			print(hl.sha512(pp.encode()).hexdigest(), file = hash_file)
			print(hint, file = hash_file)

		# decrypt the encrypted passwords in 'keys.csv' using the old AES key, 'key'
		# encrypt them using the new AES key, 'updated_key'
		# write the newly encrpyted passwords to a new file
		updated_key = hl.sha256(pp.encode()).digest()
		with open('keys.csv') as password_file, open('.keys', 'w') as updated_password_file:
			for row in password_file:
				last_comma = row.rfind(',')
				pw = row[last_comma + 1 :].strip() # last item in comma-separated list is the encrypted password
				updated_pw = encryptAES(decryptAES(pw, self.key), updated_key)
				print('{},{}'.format(row[: last_comma], updated_pw), file = updated_password_file)
		self.key = updated_key # set the new key for AES

		# clean up
		os.remove('hash')
		os.rename('.hash', 'hash')
		os.remove('keys.csv')
		os.rename('.keys', 'keys.csv')

		mb.showinfo('Passphrase Changed', 'Passphrase was changed successfully.')

		self.parent.quit()
		self.parent.destroy()

################################################################################

def locate_row_of_interest(choose_window):
	'''
	Helper function to change, delete or view a password.
	Locates which line of 'keys.csv' has to be changed, deleted or viewed.
	Instantiates Search class and Found class.
	Search class accepts a term to search in 'keys.csv' file.
	Found class chooses one out of the search results.

	Args:
		choose_window: the Choose object whose window is required to create a tk.Toplevel

	Returns:
		string (a row in 'keys.csv') which the user wants to change, delete or view (if a search is performed)
		None (if search is not performed)
	'''

	# instantiate Search class to accept a search term
	locate = tk.Toplevel(choose_window.parent)
	locate_Search = Search(locate)
	locate.mainloop()

	# list of all rows matching the search
	# if the user closed the 'locate' window without searching, this will be an empty list
	found_rows = locate_Search.search_result
	if found_rows == []:
		return None

	# instantiate Found class to display search results
	select_row = tk.Toplevel(choose_window.parent)
	select_row_Found = Found(select_row, found_rows)
	select_row.mainloop()

	# find what the user chose
	# if the user closed the 'select_row' window, this will be an empty string
	chosen_row = select_row_Found.row_of_interest
	if chosen_row == '':
		return None

	return chosen_row

################################################################################

class Search(BaseWindowClass):
	'''
	Accept a seach term from the user and search 'keys.csv' for that term.
	Search only for matching accounts, user IDs and user names (not passwords).
	'''

	def __init__(self, parent):
		super().__init__(parent)
		parent.title('Delete, Change or View a Password')
		self.search_result = []

		# header
		head_label = tk.Label(parent, text = 'Search Accounts', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# sub-header
		subhead_label = tk.Label(parent, text = 'You may leave the field blank if\nyou want a list of all accounts.')
		subhead_label.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 2, columnspan = 2, padx = 30, pady = (0, 30))

		# search prompt label
		search_label = tk.Label(parent, text = 'Search Term', font = subtitlefont)
		search_label.grid(row = 3, column = 0, padx = 30, pady = 15)

		# search prompt entry
		search_entry = tk.Entry(parent)
		search_entry.grid(row = 3, column = 1, padx = 30, pady = 15)
		search_entry.focus()

		# perform the search
		self.submit = tk.Button(parent, text = 'Search', height = 2, width = 20, command = lambda : self.search_password(search_entry.get()))
		self.submit.grid(row = 4, columnspan = 2, padx = 30, pady = 30)

	########################################

	def search_password(self, item):
		'''
		Locate all rows of 'keys.csv' file which contain the argument string.
		Each time a match is found, it is appended to 'self.search_result'.

		Args:
			self: class object
			item: the string to be searched

		Returns:
			None
		'''

		# find the string in 'keys.csv'
		with open('keys.csv') as password_file:
			for row in password_file:
				if item.lower() in row[: row.rfind(',')].lower():
					self.search_result.append(row.strip())

		# if search was unsuccessful, allow the user to try again
		if self.search_result == []:
			mb.showinfo('Nothing Found','The search term you entered could not be found.')
			return

		# search was successful--close the window
		self.parent.quit()
		self.parent.destroy()

################################################################################

class Found(BaseWindowClass):
	'''
	Obtain the list of search results provided by above Search class.
	Display all the search results in a new window using radio buttons.
	The user must select the one they are interested in.
	'''

	def __init__(self, parent, rows):
		super().__init__(parent)
		parent.title('Search Results')
		self.rows = rows
		self.row_of_interest = ''

		# header
		head_label = tk.Label(parent, text = 'Select an Account', font = titlefont)
		head_label.grid(row = 0, columnspan = 4, padx = 30, pady = (30, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 1, columnspan = 4, padx = 30, pady = (0, 30))

		# radio button selection variable
		selection = tk.IntVar(value = 2)

		# create labels in loop
		for i, row in enumerate(rows, 2):

			# rename the comma-separated items for convenience
			acc, uid, name, pw = row.split(',')

			# radio button
			choice_rbutton = tk.Radiobutton(parent, variable = selection, value = i)
			choice_rbutton.grid(row = i, column = 0, padx = (30, 0))

			# account label
			acc_label = tk.Label(parent, text = acc)
			acc_label.grid(row = i, column = 1, padx = (0, 15))

			# user ID label
			uid_label = tk.Label(parent, text = uid)
			uid_label.grid(row = i, column = 2, padx = (0, 15))

			# user name label
			name_label = tk.Label(parent, text = name)
			name_label.grid(row = i, column = 3, padx = (0, 15))

		# make selection
		self.submit = tk.Button(parent, text = 'Select', height = 2, width = 20, command = lambda : self.get_password_line(selection.get()))
		self.submit.grid(row = i + 1, columnspan = 4, padx = 30, pady = 30)

	########################################

	def get_password_line(self, row_index):
		'''
		Send the row of interest back to 'locate_row_of_interest' function.
		Do this by setting value of a class member to that string (row).

		Args:
			self: class object
			row_index: the value of the radio button the user selected

		Returns:
			None
		'''

		self.parent.quit()
		self.parent.destroy()
		self.row_of_interest = self.rows[row_index - 2]

################################################################################

def delete_password(choose_window):
	'''
	Wrapper function to instantiate the DeletePassword class.

	Args:
		choose_window: the Choose object whose window has to be hidden before displaying a new window

	Returns:
		None
	'''

	# hide the option choosing window
	choose_window.parent.withdraw()

	# obtain the row containing the password to be deleted
	row_of_interest = locate_row_of_interest(choose_window)
	if row_of_interest is None:
		choose_window.parent.deiconify() # unhide the option choosing window
		return
	deleter = tk.Toplevel(choose_window.parent)
	DeletePassword(deleter, row_of_interest)
	deleter.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

################################################################################

class DeletePassword(BaseWindowClass):
	'''
	Display the account which the user wants to delete from 'keys.csv' file.
	Ask for confirmation before deleting.
	'''

	def __init__(self, parent, row_of_interest):
		super().__init__(parent)
		parent.title('Delete a Password')

		# rename the comma-separated items for convenience
		acc, uid, name, pw = row_of_interest.split(',')

		# header
		head_label = tk.Label(parent, text = 'Confirm Delete', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		# sub-header
		subhead_label = tk.Label(parent, text = 'Confirm that you want to delete the password\nassociated with this account. This operation is\nirreversible.')
		subhead_label.grid(row = 1, columnspan = 2, padx = 30, pady = (0, 15))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 2, columnspan = 2, padx = 30, pady = (0, 30))

		# account question label
		acc_q_label = tk.Label(parent, text = 'Account', font = subtitlefont)
		acc_q_label.grid(row = 3, column = 0, padx = 30, pady = 15)

		# account answer label
		acc_a_label = tk.Label(parent, text = acc)
		acc_a_label.grid(row = 3, column = 1, padx = 30, pady = 15)

		# user ID question label
		uid_q_label = tk.Label(parent, text = 'User ID', font = subtitlefont)
		uid_q_label.grid(row = 4, column = 0, padx = 30, pady = 15)

		# user ID answer label
		uid_a_label = tk.Label(parent, text = uid)
		uid_a_label.grid(row = 4, column = 1, padx = 30, pady = 15)

		# user name question label
		name_q_label = tk.Label(parent, text = 'User Name', font = subtitlefont)
		name_q_label.grid(row = 5, column = 0, padx = 30, pady = 15)

		# user name answer label
		name_a_label = tk.Label(parent, text = name)
		name_a_label.grid(row = 5, column = 1, padx = 30, pady = 15)

		# delete the password line
		self.submit = tk.Button(parent, text = 'Delete', height = 2, width = 20, command = lambda : self.remove_pass(row_of_interest))
		self.submit.grid(row = 6, columnspan = 2, padx = 30, pady = 30)

	########################################

	def remove_pass(self, row_of_interest):
		'''
		Copy all lines in 'keys.csv' (except the line to be deleted) to a new file.
		Then rename the new file to 'keys.csv', thus deleting the password the user wanted to delete.

		Args:
			self: class object
			row_of_interest: the row (string) to be removed from 'keys.csv'

		Returns:
			None
		'''

		# confirm and delete password
		response = mb.askyesno('Confirmation', 'Delete this password? This process cannot be undone.', icon = 'warning')
		if response == False:
			return
		with open('keys.csv') as password_file, open('.keys', 'w') as updated_password_file:
			for row in password_file:
				row = row.strip()
				if row != row_of_interest:
					print(row, file = updated_password_file)

		# clean up
		os.remove('keys.csv')
		os.rename('.keys', 'keys.csv')

		mb.showinfo('Password Deleted', 'The password was deleted successfully.')

		self.parent.quit()
		self.parent.destroy()

################################################################################

def change_password(choose_window):
	'''
	Wrapper function to instantiate the ChangePassword class.

	Args:
		choose_window: the Choose object whose window has to be hidden before displaying a new window

	Returns:
		None
	'''

	# hide the option choosing window
	choose_window.parent.withdraw()

	# obtain the row containing the password to be changed
	row_of_interest = locate_row_of_interest(choose_window)
	if row_of_interest is None:
		choose_window.parent.deiconify() # unhide the option choosing window
		return
	changer = tk.Toplevel(choose_window.parent)
	ChangePassword(changer, choose_window.key, row_of_interest)
	changer.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

################################################################################

class ChangePassword(AddPassword):
	'''
	Mostly the same as AddPassword, hence inheriting it rather than BaseWindowClass.
	Only some labels and the behaviour of 'self.submit' are different.
	'''

	def __init__(self, parent, key, row_of_interest):
		super().__init__(parent, key)
		parent.title('Change a Password')

		# rename the comma-separated items for convenience
		acc, uid, name, pw = row_of_interest.split(',')

		# fill the first three fields using the previously set credentials
		# leave the password fields blank
		self.accvar.set(acc)
		self.uidvar.set(uid)
		self.namevar.set(name)

		# change the text on the 'submit' button, which is 'Add' because of inheritance
		# it should be 'Change' to reflect what this class is doing
		self.submit['text'] = 'Change'

################################################################################

if __name__ == '__main__':

	# x = 'srbsedfvvgedvgdvfoemxpuifbhasch,widj'
	# k = hl.sha256('avfegbsdvge'.encode()).digest()
	# y = encryptAES(x, k)
	# z = decryptAES(y, k)
	# print(x)
	# print(y)
	# print(z)
	# print(k)
	# raise SystemExit

	root = tk.Tk()
	root_Login = Login(root)
	root.mainloop()

	branch = tk.Tk()
	branch_Choose = Choose(branch, root_Login.key)
	branch.mainloop()
