#!/usr/bin/env python3

import base64
import Crypto.Cipher.AES as AES
import Crypto.Random as RND
import hashlib as hl
import os
import random as rnd
import string
import sys
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
phraselength = 1 # minimum passphrase length required while changing passphrase
pad = 30 # the padding used for tkinter widgets
h, w = 2, 20 # main button sizes

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
	Toggle how the contents of an Entry are displayed.
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

def restore_focus_to(window, widget = None):
	'''
	Make a window the active window. Additionally, focus on a widget of that window.
	On Windows OS, whenever a message box is closed, its tk.Toplevel or tk.Tk does not become active automatically.
	This function will make 'window' the active window and restore focus to 'widget'.
	Solving this problem is not as straightforward as simply calling 'focus_force' on the window.
	If the user closes the window when its message box was open, the window cannot be made the active window.
	Because it has been closed! In which case, this function should do nothing.

	Args:
		window: the window which has to be brought into focus
		widget: the widget within 'window' which will be focused (if provided)

	Returns:
		None
	'''

	# make the window active
	try:
		window.focus_force()
	except tk.TclError:
		print('Window was closed forcibly.')
		return

	# focus on the widget
	if widget:
		widget.focus()

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
		self.tw.overrideredirect(True)
		self.tw.geometry('+{}+{}'.format(x, y))
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

		# cross-platform trick to set application icon
		system = sys.platform
		if system == 'linux' or system == 'darwin':
			# parent.tk.call('wm', 'iconphoto', parent._w, tk.PhotoImage(file = 'wpm.gif'))
			parent.iconphoto(True, tk.PhotoImage(file = 'favicon.gif'))
		elif system == 'win32':
			parent.iconbitmap('favicon.ico')

		# always steal focus when created
		parent.focus_force()

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
		If the class does not have a 'submit' attribute, do nothing.

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
			try:
				self.submit.invoke()
			except AttributeError:
				print('No button has been selected.')

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
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (pad, pad / 4))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to quit the application.')
		inst_label.grid(row = 1, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# passphrase prompt entry
		self.pp_entry = tk.Entry(parent, show = '*')
		self.pp_entry.grid(row = 2, column = 1, padx = pad, pady = pad / 2)
		self.pp_entry.focus()

		# toggle passphrase view
		show_button = tk.Button(parent, text = 'Passphrase', font = subtitlefont, command = lambda : show_pass(self.pp_entry))
		show_button.grid(row = 2, column = 0, padx = pad, pady = pad / 2)
		CreateTooltip(show_button, 'Show or hide passphrase')

		# display hint
		hint_button = tk.Button(parent, text = 'Passphrase Hint', height = h, width = w, command = self.view_hint)
		hint_button.grid(row = 3, columnspan = 2, padx = pad, pady = (pad / 2, pad / 4))

		# check if password is correct and proceed
		self.submit = tk.Button(parent, text = 'Log In', height = h, width = w, command = self.validate_phrase)
		self.submit.grid(row = 4, columnspan = 2, padx = pad, pady = (pad / 4, pad))

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
			mb.showinfo('Passphrase Hint', hint, parent = self.parent)
			restore_focus_to(self.parent, self.pp_entry)

	########################################

	def validate_phrase(self):
		'''
		Compare the SHA-512 of the entered passphrase with the stored value.
		If they are the same, set the SHA-256 of the passphrase as the AES256 key.
		SHA-256 is conveniently 256 bits long, which is the key length of AES256.

		Args:
			self: class object
			pp: passphrase string

		Returns:
			None
		'''

		# compare the string stored in the file 'hash' with the SHA-512 of 'phrase'
		pp = self.pp_entry.get()
		pp_hash = hl.sha512(pp.encode()).hexdigest()
		with open('hash') as hash_file:
			expected_hash = hash_file.readline().strip()
		if pp_hash != expected_hash:
			mb.showerror('Wrong Passphrase', 'The passphrase entered is wrong.', parent = self.parent)
			restore_focus_to(self.parent, self.pp_entry)
			return

		# if the passphrase was correct, close this window and set 'self.key'
		# which will be used as the key for AES
		self.parent.quit()
		self.parent.destroy()
		self.key = hl.sha256(pp.encode()).digest()

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
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (pad, pad / 4))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to quit the application.')
		inst_label.grid(row = 1, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# add password
		add_button = tk.Button(parent, text = 'Add a Password', height = h, width = w, command = lambda : add_password(self))
		add_button.grid(row = 2, column = 0, padx = pad, pady = (pad / 2, pad / 4))

		# delete button
		del_button = tk.Button(parent, text = 'Delete a Password', height = h, width = w, command = lambda : delete_password(self))
		del_button.grid(row = 2, column = 1, padx = pad, pady = (pad / 2, pad / 4))

		# change password button
		cpw_button = tk.Button(parent, text = 'Change a Password', height = h, width = w, command = lambda : change_password(self))
		cpw_button.grid(row = 3, column = 0, padx = pad, pady = pad / 4)

		# view button
		view_button = tk.Button(parent, text = 'View a Password', height = h, width = w, command = lambda : view_password(self))
		view_button.grid(row = 3, column = 1, padx = pad, pady = pad / 4)

		# change passphrase button
		cpp_button = tk.Button(parent, text = 'Change Passphrase', height = h, width = w, command = lambda : change_passphrase(self))
		cpp_button.grid(row = 4, columnspan = 2, padx = pad, pady = (pad / 4, pad))

	########################################

	def close_button(self, event = None):
		raise SystemExit(0)

################################################################################

def add_password(choose_window):
	'''
	Wrapper function to instantiate 'AddPassword' class.

	Args:
		choose_window: the Choose object whose window has to be hidden before displaying a new window

	Returns:
		None
	'''

	# hide the option choosing window
	choose_window.parent.withdraw()

	adder = tk.Toplevel(choose_window.parent)
	adder_object = AddPassword(adder, choose_window.key)
	adder.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()
	choose_window.parent.focus_force()

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
		self.accvar = tk.StringVar() # for 'self.acc_entry'
		self.uidvar = tk.StringVar() # for 'self.uid_entry'
		self.namevar = tk.StringVar() # for 'self.name_entry'
		self.pwvar = tk.StringVar() # for 'self.pw_entry'
		self.cpvar = tk.StringVar() # for 'self.cp_entry'

		# header
		head_label = tk.Label(parent, text = 'Enter Credentials', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (pad, pad / 4))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 1, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# account prompt label
		acc_label = tk.Label(parent, text = 'Account', font = subtitlefont)
		acc_label.grid(row = 2, column = 0, padx = pad, pady = (pad / 2, pad / 4))

		# user ID prompt label
		uid_label = tk.Label(parent, text = 'User ID (e.g. email)', font = subtitlefont)
		uid_label.grid(row = 3, column = 0, padx = pad, pady = pad / 4)

		# user name prompt label
		name_label = tk.Label(parent, text = 'User Name', font = subtitlefont)
		name_label.grid(row = 4, column = 0, padx = pad, pady = (pad / 4, pad / 2))

		# account prompt entry
		self.acc_entry = tk.Entry(parent, textvariable = self.accvar)
		self.acc_entry.grid(row = 2, column = 1, padx = pad, pady = (pad / 2, pad / 4))
		self.acc_entry.focus()

		# user ID prompt entry
		self.uid_entry = tk.Entry(parent, textvariable = self.uidvar)
		self.uid_entry.grid(row = 3, column = 1, padx = pad, pady = pad / 4)

		# user name prompt entry
		self.name_entry = tk.Entry(parent, textvariable = self.namevar)
		self.name_entry.grid(row = 4, column = 1, padx = pad, pady = (pad / 4, pad / 2))

		# password prompt entry
		self.pw_entry = tk.Entry(parent, textvariable = self.pwvar, show = '*')
		self.pw_entry.grid(row = 6, column = 1, padx = pad, pady = (pad / 2, pad / 4))

		# confirm password prompt entry
		self.cp_entry = tk.Entry(parent, textvariable = self.cpvar, show = '*')
		self.cp_entry.grid(row = 7, column = 1, padx = pad, pady = (pad / 4, pad / 2))

		# add the password to the file
		self.submit = tk.Button(parent, text = 'Add', height = h, width = w, command = self.validate_pw)
		self.submit.grid(row = 8, columnspan = 2, padx = pad, pady = (pad / 2, pad))

		# auto-fill password entries
		autofill_button = tk.Button(parent, text = 'Suggested Password', font = subtitlefont, command = self.set_passwords)
		autofill_button.grid(row = 5, column = 0, padx = pad, pady = pad / 2)
		CreateTooltip(autofill_button, 'Auto-fill the password entries\nbelow with the suggested password')

		# refresh suggested password
		refresh_button = tk.Button(parent, textvariable = self.plvar, command = lambda : self.plvar.set(genpass(passlength)), width = pad)
		refresh_button.grid(row = 5, column = 1, padx = pad, pady = pad / 2)
		CreateTooltip(refresh_button, 'Re-generate suggested password')

		# toggle password view
		pass_button = tk.Button(parent, text = 'Password', font = subtitlefont, command = lambda : show_pass(self.pw_entry))
		pass_button.grid(row = 6, column = 0, padx = pad, pady = (pad / 2, pad / 4))
		CreateTooltip(pass_button, 'Show or hide password')

		# toggle confirm password view
		cpass_button = tk.Button(parent, text = 'Confirm Password', font = subtitlefont, command = lambda : show_pass(self.cp_entry))
		cpass_button.grid(row = 7, column = 0, padx = pad, pady = (pad / 4, pad / 2))
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

	def validate_pw(self):
		'''
		Check whether the credentials provided by the user are appropriate.
		The account, user ID, user name and password entries must not be empty.
		Both password entries must have the same string.
		There must be no comma in the account, user ID and user name entries.

		Args:
			self: class object
			credentials: list of credential strings the user entered

		Returns:
			None
		'''

		# create a list of the entries which have to be validated
		entries = [self.acc_entry, self.uid_entry, self.name_entry, self.pw_entry, self.cp_entry]

		# this should check for empty Entries
		# the first empty Entry should get focus after a specific error message is displayed
		for entry in entries:
			if entry.get() == '':
				mb.showerror('Empty Field', 'One or more fields are empty. Fill all of them to proceed.', parent = self.parent)
				restore_focus_to(self.parent, entry)
				return

		# the credentials are stored in CSV format
		# hence, commas are not allowed in the first three fields
		for entry in entries[: 3]:
			if ',' in entry.get():
				mb.showerror('Invalid Input', 'The \'Account\', \'User ID\' and \'User Name\' fields must not contain commas.', parent = self.parent)
				restore_focus_to(self.parent, entry)
				return

		# check whether the two passwords entered are identical
		if self.pw_entry.get() != self.cp_entry.get():
			mb.showerror('Password Mismatch', 'The \'Password\' and \'Confirm Password\' fields do not match.', parent = self.parent)
			restore_focus_to(self.parent, self.pw_entry)
			return

		# validation is done
		# the actual process of adding the password is left to the following function
		# this class will be inherited by 'ChangePassword' class
		# in the latter class, only that function will have to be changed
		# so that in 'ChangePassword', the function changes instead of adds password
		self.add_or_change(entries[: -1]) # no need to send 'Confirm Password'

	########################################

	def add_or_change(self, entries):
		'''
		Add the credentials provided to 'keys.csv' file.

		Args:
			self: class object
			entries: list of entries which contain credentials to be written to 'keys.csv'

		Returns:
			None
		'''

		# confirm
		previously_focused_widget = self.parent.focus_get() # to get back focus after message box is closed
		response = mb.askyesno('Confirmation', 'Add password?', icon = 'warning', parent = self.parent)
		if response == False:
			restore_focus_to(self.parent, previously_focused_widget)
			return

		# obtain the strings in the entries provided
		acc, uid, name, pw = [entry.get() for entry in entries]

		# write the credentials to the file 'keys.csv'
		with open('keys.csv', 'a') as password_file:
			print('{},{},{},{}'.format(acc, uid, name, encryptAES(pw, self.key)), file = password_file)

		mb.showinfo('Password Added', 'Password for {} was added successfully.'.format(name), parent = self.parent)

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
	updater_object = ChangePassphrase(updater, choose_window.key)
	updater.mainloop()
	choose_window.key = updater_object.key # set the updated key

	# unhide the option choosing window
	choose_window.parent.deiconify()
	choose_window.parent.focus_force()

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
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (pad, pad / 4))

		# sub-header
		subhead_label = tk.Label(parent, text = 'Use a long easy-to-remember passphrase.\nAvoid a short random one. Include special characters!')
		subhead_label.grid(row = 1, columnspan = 2, padx = pad, pady = pad / 4)

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 2, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# passphrase hint prompt label
		hint_label = tk.Label(parent, text = 'Passphrase Hint', font = subtitlefont)
		hint_label.grid(row = 5, column = 0, padx = pad, pady = (pad / 4, pad / 2))

		# passphrase prompt entry
		self.pp_entry = tk.Entry(parent, show = '*')
		self.pp_entry.grid(row = 3, column = 1, padx = pad, pady = (pad / 2, pad / 4))
		self.pp_entry.focus()

		# confirm passphrase prompt entry
		self.cp_entry = tk.Entry(parent, show = '*')
		self.cp_entry.grid(row = 4, column = 1, padx = pad, pady = pad / 4)

		# passphrase hint prompt entry
		self.hint_entry = tk.Entry(parent)
		self.hint_entry.grid(row = 5, column = 1, padx = pad, pady = (pad / 4, pad / 2))

		# change the passphrase
		self.submit = tk.Button(parent, text = 'Change', height = h, width = w, command = self.update_phrase)
		self.submit.grid(row = 6, columnspan = 2, padx = pad, pady = (pad / 2, pad))

		# toggle passphrase view
		pp_button = tk.Button(parent, text = 'New Passphrase', font = subtitlefont, command = lambda : show_pass(self.pp_entry))
		pp_button.grid(row = 3, column = 0, padx = pad, pady = (pad / 2, pad / 4))
		CreateTooltip(pp_button, 'Show or hide passphrase')

		# toggle confirm passphrase view
		cp_button = tk.Button(parent, text = 'Confirm Passphrase', font = subtitlefont, command = lambda : show_pass(self.cp_entry))
		cp_button.grid(row = 4, column = 0, padx = pad, pady = pad / 4)
		CreateTooltip(cp_button, 'Show or hide passphrase')

	########################################

	def update_phrase(self):
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

		# obtain the strings entered
		pp = self.pp_entry.get()
		cp = self.cp_entry.get()
		hint = self.hint_entry.get()

		# check passphrase length
		if len(pp) < phraselength:
			mb.showerror('Invalid Passphrase', 'The passphrase should be at least {} characters long.'.format(phraselength), parent = self.parent)
			restore_focus_to(self.parent, self.pp_entry)
			return

		# compare passphrases
		if pp != cp:
			mb.showerror('Passphrase Mismatch', 'The \'New Passphrase\' and \'Confirm Passphrase\' fields do not match.', parent = self.parent)
			restore_focus_to(self.parent, self.pp_entry)
			return

		# passphrase hint is necessary
		if hint == '':
			mb.showerror('Hint Required', 'You must provide a hint for the new passphrase.', parent = self.parent)
			restore_focus_to(self.parent, self.hint_entry)
			return

		# confirm
		previously_focused_widget = self.parent.focus_get() # to get back focus after message box is closed
		response = mb.askyesno('Confirmation', 'Change Passphrase?', icon = 'warning', parent = self.parent)
		if response == False:
			restore_focus_to(self.parent, previously_focused_widget)
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

		mb.showinfo('Passphrase Changed', 'Passphrase was changed successfully.', parent = self.parent)

		self.parent.quit()
		self.parent.destroy()

################################################################################

def locate_row_of_interest(choose_window):
	'''
	Helper function to change, delete or view a password.
	Locates which line of 'keys.csv' has to be changed, deleted or viewed.
	Instantiates 'Search' class.

	Args:
		choose_window: the Choose object whose window is required to create a tk.Toplevel

	Returns:
		string (a row in 'keys.csv') which the user wants to change, delete or view (if a search is performed)
		None (if search is not performed)
	'''

	# instantiate Search class to accept a search term
	locate = tk.Toplevel(choose_window.parent)
	locate_object = Search(locate)
	locate.mainloop()

	# find what the user chose
	# if the user did not choose any, this will be an empty string
	chosen_row = locate_object.row_of_interest
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
		self.rows = '' # list of rows matching the search
		self.selection = tk.IntVar(value = 0) # radio button selection variable
		self.row_of_interest = '' # row of 'self.rows' corresponding to the radio button selected
		self.searchvar = tk.StringVar() # string the user enters as the 'Search Term'
		self.widgets_in_frame_canvas = [] # list of widgets in 'self.frame_canvas'

		# store all rows of 'keys.csv' in a member variable
		# that way, while searching, file need not be opened
		with open('keys.csv') as password_file:
			self.everything = password_file.readlines()

		# whenever the user types something new, update the search results
		self.searchvar.trace_add('write', lambda *dummy : self.populate_frame_canvas(self))

		# frame to display headings and tk.Entry
		topframe = tk.Frame(parent)
		topframe.grid(row = 0, pady = (pad, pad / 2))

		# header
		head_label = tk.Label(topframe, text = 'Search Accounts', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (0, pad / 4))

		# sub-header
		subhead_label = tk.Label(topframe, text = 'Enter a search term to narrow the list down.')
		subhead_label.grid(row = 1, columnspan = 2, padx = pad, pady = pad / 4)

		# keyboard instruction
		inst_label = tk.Label(topframe, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 2, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# search prompt label
		search_label = tk.Label(topframe, text = 'Search Term', font = subtitlefont)
		search_label.grid(row = 3, column = 0, padx = pad, pady = (pad / 2, 0))

		# search prompt entry
		self.search_entry = tk.Entry(topframe, textvariable = self.searchvar)
		self.search_entry.grid(row = 3, column = 1, padx = pad, pady = (pad / 2, 0))
		self.search_entry.focus()

		# frame to contain scrollable canvas
		middleframe = tk.Frame(parent)
		middleframe.grid(row = 1, padx = pad, pady = pad / 2)

		# above-mentioned canvas
		canvas = tk.Canvas(middleframe)
		canvas.grid(row = 0, column = 0)
		# canvas.bind_all("<Button-4>", self._on_mousewheel)
		canvas.bind_all('<Button-4>', lambda *dummy : canvas.yview_scroll(-1 * event.delta / 120, 'units'))
		# https://stackoverflow.com/questions/17355902/python-tkinter-binding-mousewheel-to-scrollbar
		# bind mouse wheel to scroll

		# scrollbars
		vsb = tk.Scrollbar(middleframe, orient = 'vertical', command = canvas.yview)
		vsb.grid(row = 0, column = 1, sticky = 'ns')
		canvas.configure(yscrollcommand = vsb.set)
		hsb = tk.Scrollbar(middleframe, orient = 'horizontal', command = canvas.xview)
		hsb.grid(row = 1, column = 0, sticky = 'we')
		canvas.configure(xscrollcommand = hsb.set)

		# frame inside canvas to display radio button list
		self.frame_canvas = tk.Frame(canvas)
		canvas.create_window((0, 0), window = self.frame_canvas, anchor = 'nw')
		self.populate_frame_canvas()
		canvas.config(scrollregion = canvas.bbox('all'))

		# choose the radio button selected
		self.submit = tk.Button(parent, text = 'Select', height = h, width = w, command = self.set_row)
		self.submit.grid(row = 2, padx = pad, pady = (pad / 2, pad))

	########################################

	def _on_mousewheel(self, event):
		self.canvas.yview_scroll(int(-1*(event.delta)), "units")

	########################################

	def populate_frame_canvas(self, event = None):
		'''
		Scan the string the user typed in the 'search_entry'.
		If this is empty, populate the frame with everything in 'keys.csv'.
		Otherwise, populate it with whatever matches the string.

		Args:
			self: class object

		Returns:
			None
		'''

		# clean up the effects of previous search, if any
		for widget in self.widgets_in_frame_canvas:
			widget.destroy() # delete the widgets already present in the 'self.frame_canvas'
		self.rows = [] # clear the previous search results
		i = 0 # counter to count the rows which get appended to 'self.rows'
		self.selection.set(0) # initially, always keep the first radio button selected

		# look for rows in 'keys.csv' which match the search
		# contents of 'keys.csv' have already been loaded in 'self.everything'
		# create those widgets in 'self.frame_canvas'
		for row in self.everything:

			# display 'row' only if it contains the search term
			if self.searchvar.get().lower() in row[: row.rfind(',')].lower():

				# radio button
				rb = tk.Radiobutton(self.frame_canvas, variable = self.selection, value = i)
				rb.grid(row = i, column = 0)

				# break the string 'row'
				acc, uid, name, pw = row.split(',')

				# account label
				acc_label = tk.Label(self.frame_canvas, text = acc)
				acc_label.grid(row = i, column = 1, padx = (0, pad / 8))

				# user ID label
				uid_label = tk.Label(self.frame_canvas, text = uid)
				uid_label.grid(row = i, column = 2, padx = pad / 8)

				# user name label
				name_label = tk.Label(self.frame_canvas, text = name)
				name_label.grid(row = i, column = 3, padx = (pad / 8, 0))

				# save all of them in a list
				# so that they can be deleted the next time a search occurs
				self.widgets_in_frame_canvas.append(rb)
				self.widgets_in_frame_canvas.append(acc_label)
				self.widgets_in_frame_canvas.append(uid_label)
				self.widgets_in_frame_canvas.append(name_label)

				# also save 'row' because it has to be forwarded
				# it is required to delete, change or view passwords
				self.rows.append(row)

				# increment counter only if a row was appended
				i += 1

		# calculate widget sizes
		self.frame_canvas.update_idletasks()

	########################################

	def set_row(self):
		'''
		Set the member variable to the item which has its radio button selected.

		Args:
			self: class object

		Returns:
			None
		'''

		# if the search was successful, set a member variable to the chosen item
		# then exit from here
		try:
			self.row_of_interest = self.rows[self.selection.get()].strip()

			self.parent.quit()
			self.parent.destroy()

		# if the search was unsuccessful, 'self.rows' will be an empty list
		# becuse nothing gets appended to it in above 'populate_frame_canvas' function
		# hence, IndexError will occur
		except IndexError:
			mb.showerror('Nothing Found', 'The item you are searching for could not be found in your password file.')
			restore_focus_to(self.parent, self.search_entry)

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
	deleter_object = DeletePassword(deleter, row_of_interest)
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
		self.row_of_interest = row_of_interest

		# rename the comma-separated items for convenience
		acc, uid, name, pw = row_of_interest.split(',')

		# header
		head_label = tk.Label(parent, text = 'Confirm Delete', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (pad, pad / 4))

		# sub-header
		subhead_label = tk.Label(parent, text = 'Confirm that you want to delete the password\nassociated with this account. This operation is\nirreversible.')
		subhead_label.grid(row = 1, columnspan = 2, padx = pad, pady = (pad / 4, pad / 4))

		# keyboard instruction
		inst_label = tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.')
		inst_label.grid(row = 2, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# account question label
		acc_q_label = tk.Label(parent, text = 'Account', font = subtitlefont)
		acc_q_label.grid(row = 3, column = 0, padx = pad, pady = (pad / 2, pad / 4))

		# account answer label
		acc_a_label = tk.Label(parent, text = acc)
		acc_a_label.grid(row = 3, column = 1, padx = pad, pady = (pad / 2, pad / 4))

		# user ID question label
		uid_q_label = tk.Label(parent, text = 'User ID', font = subtitlefont)
		uid_q_label.grid(row = 4, column = 0, padx = pad, pady = pad / 4)

		# user ID answer label
		uid_a_label = tk.Label(parent, text = uid)
		uid_a_label.grid(row = 4, column = 1, padx = pad, pady = pad / 4)

		# user name question label
		name_q_label = tk.Label(parent, text = 'User Name', font = subtitlefont)
		name_q_label.grid(row = 5, column = 0, padx = pad, pady = (pad / 4, pad / 2))

		# user name answer label
		name_a_label = tk.Label(parent, text = name)
		name_a_label.grid(row = 5, column = 1, padx = pad, pady = (pad / 4, pad / 2))

		# delete the password line
		self.submit = tk.Button(parent, text = 'Delete', height = h, width = w, command = self.remove_pass)
		self.submit.grid(row = 6, columnspan = 2, padx = pad, pady = (pad / 2, pad))

	########################################

	def remove_pass(self):
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
		response = mb.askyesno('Confirmation', 'Delete password? This process cannot be undone.', icon = 'warning', parent = self.parent)
		if response == False:
			restore_focus_to(self.parent)
			return
		with open('keys.csv') as password_file, open('.keys', 'w') as updated_password_file:
			for row in password_file:
				row = row.strip()
				if row != self.row_of_interest:
					print(row, file = updated_password_file)

		# clean up
		os.remove('keys.csv')
		os.rename('.keys', 'keys.csv')

		mb.showinfo('Password Deleted', 'Password was deleted successfully.', parent = self.parent)

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
	changer_object = ChangePassword(changer, choose_window.key, row_of_interest)
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
		self.row_of_interest = row_of_interest

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

	########################################

	def add_or_change(self, entries):
		'''
		Inherited from 'AddPassword', where this function adds a new line to 'keys.csv'
		In this class, it must change the line which matches 'self.row_of_interest'
		Change it to what is provided in 'entries'.
		Write the result to a new file. Delete the old file and rename the new one.

		Args:
			self: class object
			entries: list of entries which contain new credentials

		Returns:
			None
		'''

		# confirm
		previously_focused_widget = self.parent.focus_get() # to get back focus after message box is closed
		response = mb.askyesno('Confirmation', 'Change password?', icon = 'warning', parent = self.parent)
		if response == False:
			restore_focus_to(self.parent, previously_focused_widget)
			return

		# obtain the strings in the entries provided
		acc, uid, name, pw = [entry.get() for entry in entries]

		# write the new credentials to a new file
		with open('keys.csv') as password_file, open('.keys', 'w') as updated_password_file:
			for row in password_file:
				row = row.strip()
				if row != self.row_of_interest:
					print(row, file = updated_password_file)
				else:
					print('{},{},{},{}'.format(acc, uid, name, encryptAES(pw, self.key)), file = updated_password_file)

		# clean up
		os.remove('keys.csv')
		os.rename('.keys', 'keys.csv')

		mb.showinfo('Password Changed', 'Password for {} was changed successfully.'.format(name), parent = self.parent)

		self.parent.quit()
		self.parent.destroy()

################################################################################

def view_password(choose_window):
	'''
	Wrapper function to instantiate the ViewPassword class.

	Args:
		choose_window: the Choose object whose window has to be hidden before displaying a new window

	Returns:
		None
	'''

	# hide the option choosing window
	choose_window.parent.withdraw()

	# obtain the row containing the password to be viewed
	row_of_interest = locate_row_of_interest(choose_window)
	if row_of_interest is None:
		choose_window.parent.deiconify()
		return
	viewer = tk.Toplevel(choose_window.parent)
	viewer_object = ViewPassword(viewer, choose_window.key, row_of_interest)
	viewer.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

################################################################################

class ViewPassword(BaseWindowClass):
	'''
	Display a password in raw form.
	'''

	def __init__(self, parent, key, row_of_interest):
		super().__init__(parent)
		parent.title('View a Password')

		# rename credentials for convenience
		acc, uid, name, pw = row_of_interest.split(',')

		# header
		head_label = tk.Label(parent, text = 'View Credentials', font = titlefont)
		head_label.grid(row = 0, columnspan = 2, padx = pad, pady = (pad, pad / 4))

		# sub-header
		subhead_label = tk.Label(parent, text = 'Your credentials are as shown.')
		subhead_label.grid(row = 1, columnspan = 2, padx = pad, pady = (pad / 4, pad / 2))

		# account question label
		acc_q_label = tk.Label(parent, text = 'Account', font = subtitlefont)
		acc_q_label.grid(row = 2, column = 0, padx = pad, pady = (pad / 2, pad / 4))

		# account answer label
		acc_a_label = tk.Label(parent, text = acc)
		acc_a_label.grid(row = 2, column = 1, padx = pad, pady = (pad / 2, pad / 4))

		# user ID question label
		uid_q_label = tk.Label(parent, text = 'User ID', font = subtitlefont)
		uid_q_label.grid(row = 3, column = 0, padx = pad, pady = pad / 4)

		# user ID answer label
		uid_a_label = tk.Label(parent, text = uid)
		uid_a_label.grid(row = 3, column = 1, padx = pad, pady = pad / 4)

		# user name question label
		name_q_label = tk.Label(parent, text = 'User Name', font = subtitlefont)
		name_q_label.grid(row = 4, column = 0, padx = pad, pady = pad / 4)

		# user name answer label
		name_a_label = tk.Label(parent, text = name)
		name_a_label.grid(row = 4, column = 1, padx = pad, pady = pad / 4)

		# password question label
		pw_q_label = tk.Label(parent, text = 'Password', font = subtitlefont)
		pw_q_label.grid(row = 5, column = 0, padx = pad, pady = (pad / 4, pad / 2))

		# password answer label
		pw_a_label = tk.Label(parent, text = decryptAES(pw, key))
		pw_a_label.grid(row = 5, column = 1, padx = pad, pady = (pad / 4, pad / 2))

		# return to main menu
		self.submit = tk.Button(parent, text = 'Done', height = h, width = w, command = self.close_button)
		self.submit.grid(row = 6, columnspan = 2, padx = pad, pady = (pad / 2, pad))

################################################################################

def handle_missing_files(hash_exists, keys_exists):
	'''
	Create the files which are missing, 'keys.csv' and 'hash'.
	Interpret what to do if one already exists, but not the other.
	If both are present, do nothing.

	Args:
		hash_exists: boolean, whether 'hash' file exists
		keys_exists: boolean, whether 'keys.csv' file exists

	Returns:
		None
	'''

	# both present
	if hash_exists and keys_exists:
		return

	# create 'keys.csv' if it is missing
	if not keys_exists:
		open('keys.csv', 'w').close()

	# phantom window
	# required to show the messagebox without another window popping up
	root = tk.Tk()
	root.withdraw()

	# at this point, 'keys.csv' exists for sure, because it was created, as seen above
	# if 'keys.csv' is not empty, it means I didn't create it (it was already present)
	# in that case, 'hash' file does not exist
	# if it did, the first 'if' condition would have been executed
	# so, terminate the program, because without 'hash', the contents of 'keys.csv' cannot be used
	if os.stat('keys.csv').st_size:
		mb.showerror('Missing File', 'The file \'hash\' is missing. It is required to log in to the application. Without it, your password file \'keys.csv\' is unusable.', parent = root)
		raise SystemExit(1)

	# at this point, 'keys.csv' exists and is empty
	# if 'hash' is missing, create it with the default contents
	if not hash_exists:
		response = mb.askyesno('First Time User?', 'The file \'hash\' is missing. It is required to log in to the application. It will be created with \'root\' as the default passphrase.', icon = 'warning', parent = root)
		if response == False:
			raise SystemExit(0)
		with open('hash', 'w') as hash_file:
			print(hl.sha512('root'.encode()).hexdigest(), file = hash_file)
			print('The default passphrase is \'root\'.', file = hash_file)

	# close the phantom window
	root.quit()
	root.destroy()

################################################################################

if __name__ == '__main__':

	# take care of the possibility of 'hash' or 'keys.csv' being missing
	handle_missing_files(os.path.isfile('hash'), os.path.isfile('keys.csv'))

	# window to enter passphrase
	login = tk.Tk()
	login_object = Login(login)
	login.mainloop()

	# window to make a selection
	choose = tk.Tk()
	choose_object = Choose(choose, login_object.key)
	choose.mainloop()
