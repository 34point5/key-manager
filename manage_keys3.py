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
	'''

	return ''.join(rnd.choice(2 * string.ascii_letters + string.digits + string.punctuation) for _ in range(n))

################################################################################

def show_pass(entry_name):
	'''
		Toggle how the contents of the argument (an Entry) are displayed.
		Change the display mode from asterisks to normal and vice versa.
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
	ciphertext = base64.b64encode(initialization_vector + encryption_suite.encrypt(plaintext.encode())).decode()
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

	# when the mouse hovers over a button, display the tip
	def enter(self, event):

		# locate the tip box
		x, y, cx, cy = self.widget.bbox('insert')
		x += self.widget.winfo_rootx() + 25
		y += self.widget.winfo_rooty() + 30

		# the tip box is a tk.Toplevel with its title bar removed
		self.tw = tk.Toplevel(self.widget)
		self.tw.wm_overrideredirect(True)
		self.tw.wm_geometry('+%d+%d' % (x, y))
		tk.Label(self.tw, text = self.text).pack()

	# close the tip when the mouse moves out of the button area
	def leave(self, event):
		if self.tw:
			self.tw.destroy()

################################################################################

class Login:
	'''
		Take the master password of the user as input.
		Compute its SHA-512 and compare it with the stored SHA-512.
		If they are different, show an error message and allow retrying.
		Otherwise, the user is logged in and can use the application.
	'''

	def __init__(self, parent):
		self.parent = parent
		parent.title('Log In')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', lambda event : self.validate_phrase(phrase_entry.get()))
		parent.iconphoto(True, tk.PhotoImage(file = 'wpm.png'))

		# labels
		tk.Label(parent, text = 'Enter Passphrase', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Press \'Esc\' to quit the application.').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		# entries
		phrase_entry = tk.Entry(parent, show = '*')
		phrase_entry.grid(row = 2, column = 1, padx = 30, pady = 15)
		phrase_entry.focus()

		# buttons
		show_button = tk.Button(parent, text = 'Passphrase', font = subtitlefont, command = lambda : show_pass(phrase_entry))
		show_button.grid(row = 2, column = 0, padx = 30, pady = 15)
		CreateTooltip(show_button, 'Show or hide passphrase')

		tk.Button(parent, text = 'Passphrase Hint', height = 2, width = 20, command = self.view_hint).grid(row = 3, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Button(parent, text = 'Log In', height = 2, width = 20, command = lambda : self.validate_phrase(phrase_entry.get())).grid(row = 4, columnspan = 2, padx = 30, pady = (15, 30))

	def close_button(self, event = None):
		raise SystemExit(0)

	def view_hint(self):
		with open('hash') as hash_file:
			hint = hash_file.readlines()[1].strip()
			mb.showinfo('Passphrase Hint', hint)

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

################################################################################

class Choose:
	'''
		Ask what the user would like to do.
		Options are adding, deleting, changing and viewing any of the AES-encrypted passwords,
		and changing the master password.
	'''

	def __init__(self, parent, AES_key):
		self.parent = parent
		self.AES_key = AES_key
		parent.title('Password Manager Main Menu')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', self.press_enter)

		# labels
		tk.Label(parent, text = 'What would you like to do?', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Press \'Esc\' to quit the application.').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		# buttons
		tk.Button(parent, text = 'Add a Password', height = 2, width = 20, command = lambda : add_password(self)).grid(row = 2, column = 0, padx = 30, pady = 15)

		tk.Button(parent, text = 'Delete a Password', height = 2, width = 20, command = lambda : delete_password(self)).grid(row = 2, column = 1, padx = 30, pady = 15)

		tk.Button(parent, text = 'Change a Password', height = 2, width = 20, command = lambda : change_password(self)).grid(row = 3, column = 0, padx = 30, pady = 15)

		tk.Button(parent, text = 'View a Password', height = 2, width = 20, command = lambda : view_password(self)).grid(row = 3, column = 1, padx = 30, pady = 15)

		tk.Button(parent, text = 'Change Passphrase', height = 2, width = 20, command = lambda : change_passphrase(self)).grid(row = 4, columnspan = 2, padx = 30, pady = (15, 30))

	def close_button(self, event = None):
		raise SystemExit(0)

	# in the main menu, pressing 'Enter' should select the button in focus
	def press_enter(self, event = None):
		widget = self.parent.focus_get()
		if widget != self.parent:
			widget.invoke()

################################################################################

def add_password(choose_window):
	'''
		Wrapper function to instantiate the AddAPassword class.
	'''

	# hide the option choosing window
	choose_window.parent.wm_withdraw()

	adder = tk.Toplevel(choose_window.parent)
	AddAPassword(adder, choose_window.AES_key)
	adder.focus_set() # check if this works on Windows
	adder.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

class AddAPassword:
	'''
		Show a window to add a new password.
		Make sure that none of the entries contain a comma, because that would break 'keys.csv' format.
		Encrypt the password using 256-bit AES and store the credentials in that file.
	'''

	def __init__(self, parent, AES_key):
		self.parent = parent
		self.AES_key = AES_key
		self.labelpassvar = tk.StringVar(value = genpass(18)) # for suggested password button
		self.passwordvar = tk.StringVar() # for password entry
		self.cpasswordvar = tk.StringVar() # for confirm password entry
		parent.title('Add a Password')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', lambda event : self.validate_pw(acc_entry.get(), ID_entry.get(), name_entry.get(), pw_entry.get(), cpw_entry.get()))

		# labels
		tk.Label(parent, text = 'Enter Credentials', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		tk.Label(parent, text = 'Account', font = subtitlefont).grid(row = 2, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = 'User ID (e.g. email)', font = subtitlefont).grid(row = 3, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = 'User Name', font = subtitlefont).grid(row = 4, column = 0, padx = 30, pady = 15)

		# entries
		acc_entry = tk.Entry(parent)
		acc_entry.grid(row = 2, column = 1, padx = 30, pady = 15)
		acc_entry.focus()

		ID_entry = tk.Entry(parent)
		ID_entry.grid(row = 3, column = 1, padx = 30, pady = 15)

		name_entry = tk.Entry(parent)
		name_entry.grid(row = 4, column = 1, padx = 30, pady = 15)

		pw_entry = tk.Entry(parent, textvariable = self.passwordvar, show = '*')
		pw_entry.grid(row = 6, column = 1, padx = 30, pady = 15)

		cpw_entry = tk.Entry(parent, textvariable = self.cpasswordvar, show = '*')
		cpw_entry.grid(row = 7, column = 1, padx = 30, pady = 15)

		# buttons
		autofill_button = tk.Button(parent, text = 'Suggested Password', font = subtitlefont, command = self.set_passwords)
		autofill_button.grid(row = 5, column = 0, padx = 30, pady = 15)
		CreateTooltip(autofill_button, 'Auto-fill the password entries\nbelow with the suggested password')

		refresh_button = tk.Button(parent, textvariable = self.labelpassvar, command = self.renew_suggestion, width = 30)
		refresh_button.grid(row = 5, column = 1, padx = 30, pady = 15)
		CreateTooltip(refresh_button, 'Re-generate suggested password')

		pass_button = tk.Button(parent, text = 'Password', font = subtitlefont, command = lambda : show_pass(pw_entry))
		pass_button.grid(row = 6, column = 0, padx = 30, pady = 15)
		CreateTooltip(pass_button, 'Show or hide password')

		cpass_button = tk.Button(parent, text = 'Confirm Password', font = subtitlefont, command = lambda : show_pass(cpw_entry))
		cpass_button.grid(row = 7, column = 0, padx = 30, pady = 15)
		CreateTooltip(cpass_button, 'Show or hide password')

		tk.Button(parent, text = 'Add', height = 2, width = 20, command = lambda : self.validate_pw(acc_entry.get(), ID_entry.get(), name_entry.get(), pw_entry.get(), cpw_entry.get())).grid(row = 8, columnspan = 2, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	# change the suggested password
	def renew_suggestion(self):
		self.labelpassvar.set(genpass(18))

	# 'Suggested Password' button event
	def set_passwords(self):
		self.passwordvar.set(self.labelpassvar.get())
		self.cpasswordvar.set(self.labelpassvar.get())

	# 'Add' button event
	def validate_pw(self, *credentials):

		# rename the credentials
		account, ID, name, password, confirm_password = credentials

		# check if any field is empty
		if '' in credentials:
			mb.showerror('Empty Input', 'One or more fields are still empty. Fill all of them to proceed.')
			return

		# check if any of 'account', 'ID' or 'name' contains a comma
		if ',' in ''.join(credentials[: 3]):
			mb.showerror('Invalid Input', 'The \'Account\', \'User ID\' and \'User Name\' fields must not contain commas.')
			return

		# check passwords
		if password != confirm_password:
			mb.showerror('Password Mismatch', 'The \'Password\' and \'Confirm Password\' fields do not match.')
			return

		# get confirmation
		response = mb.askyesno('Confirmation', 'Add this password?', icon = 'warning')
		if response == False:
			return

		# write the password to the file
		with open('keys.csv', 'a') as password_file:
			password_file.write('%s,%s,%s,%s\n' % (account, ID, name, encryptAES(password, self.AES_key)))
		mb.showinfo('Password Added', 'Password for %s was added successfully.' % name)

		self.parent.quit()
		self.parent.destroy()

################################################################################

def change_passphrase(choose_window):
	'''
		Wrapper function to instantiate the ChangePassphrase class.
	'''

	# hide the option choosing window
	choose_window.parent.wm_withdraw()

	updater = tk.Toplevel(choose_window.parent)
	updater_ChangePassphrase = ChangePassphrase(updater, choose_window.AES_key)
	updater.mainloop()
	choose_window.AES_key = updater_ChangePassphrase.AES_key # set the updated AES_key

	# unhide the option choosing window
	choose_window.parent.deiconify()

class ChangePassphrase:
	'''
		Change the passphrase that must be entered to log in.
		The passwords have been encrypted using 'AES_key', which is obtained from the passphrase.
		Hence, if the passphrase is changed, 'AES_key' will also change.
		Therefore, after the passphrase is changed, decrypt the stored passwords using the old value of 'AES_key'.
		Then encrypt them using the new value of 'AES_key'.
		This new value of 'AES_key' must be sent back to the main menu.
		It is done using 'self.AES_key' attribute.
	'''

	def __init__(self, parent, AES_key):
		self.parent = parent
		self.AES_key = AES_key
		parent.title('Change Passphrase')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', lambda event : self.update_phrase(phrase_entry.get(), cphrase_entry.get(), hint_entry.get()))

		# labels
		tk.Label(parent, text = 'Enter new Passphrase', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Use a long easy-to-remember passphrase.\nAvoid a short random one. Include special characters!').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 15))

		tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.').grid(row = 2, columnspan = 2, padx = 30, pady = (0, 30))

		tk.Label(parent, text = 'Passphrase Hint', font = subtitlefont).grid(row = 5, column = 0, padx = 30, pady = 15)

		# entries
		phrase_entry = tk.Entry(parent, show = '*')
		phrase_entry.grid(row = 3, column = 1, padx = 30, pady = 15)
		phrase_entry.focus()

		cphrase_entry = tk.Entry(parent, show = '*')
		cphrase_entry.grid(row = 4, column = 1, padx = 30, pady = 15)

		hint_entry = tk.Entry(parent)
		hint_entry.grid(row = 5, column = 1, padx = 30, pady = 15)

		# buttons
		phrase_button = tk.Button(parent, text = 'Passphrase', font = subtitlefont, command = lambda : show_pass(phrase_entry))
		phrase_button.grid(row = 3, column = 0, padx = 30, pady = 15)
		CreateTooltip(phrase_button, 'Show or hide passphrase')

		cphrase_button = tk.Button(parent, text = 'Confirm Passphrase', font = subtitlefont, command = lambda : show_pass(cphrase_entry))
		cphrase_button.grid(row = 4, column = 0, padx = 30, pady = 15)
		CreateTooltip(cphrase_button, 'Show or hide passphrase')

		tk.Button(parent, text = 'Change', height = 2, width = 20, command = lambda : self.update_phrase(phrase_entry.get(), cphrase_entry.get(), hint_entry.get())).grid(row = 6, columnspan = 2, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	# 'Change' button event
	def update_phrase(self, phrase, cphrase, hint):

		# check the length of the password (comment only while developing the application)
		if len(phrase) < 24:
			mb.showerror('Invalid Passphrase', 'The passphrase should be at least 24 characters long.')
			return

		# check if the two are the same
		if phrase != cphrase:
			mb.showerror('Passphrase Mismatch', 'The \'Passphrase\' and \'Confirm Passphrase\' fields do not match.')
			return

		# user must provide a passphrase hint
		if hint == '':
			mb.showerror('Hint Required', 'You must provide a hint for the passphrase.')
			return

		# get confirmation
		response = mb.askyesno('Confirmation', 'Change Passphrase?', icon = 'warning')
		if response == False:
			return

		# write the SHA-512 of the new passphrase and the hint to a temporary file
		with open('.hash', 'w') as hash_file:
			print(hl.sha512(phrase.encode()).hexdigest(), file = hash_file)
			print(hint, file = hash_file)

		# read the passwords in 'keys.csv' one by one
		# decypt them using 'AES_key'
		# encrypt them using 'updated_AES_key'
		# write them to a temporary file
		updated_AES_key = hl.sha256(phrase.encode()).digest()
		with open('keys.csv') as password_file:
			row = password_file.readline().strip()
			with open('.keys', 'w') as updated_password_file:
				while row != '':
					lastcomma = row.rfind(',')
					password = row[lastcomma + 1 :]
					updated_password = encryptAES(decryptAES(password, self.AES_key), updated_AES_key)
					updated_password_file.write('%s,%s\n' % (row[: lastcomma], updated_password))
					row = password_file.readline().strip()
		self.AES_key = updated_AES_key

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
		Wrapper function which searches the required row in the password file.
		This is the row containing the password the user wants to delete, change or view.
		Return 'None' if a search was not performed.
		Return 'None' if a search was performed but a search result was not chosen.
		Else, return the chosen search result.
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

class Search:
	'''
		Window to allow the user to search the password file for a desired entry.
		Searching for commas is meaningless, because the password file is a CSV file.
		Set a class member variable according to the search result.
	'''

	def __init__(self, parent):
		self.parent = parent
		self.search_result = []
		parent.title('Delete, Change or View a Password')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', lambda event : self.search_password(search_entry.get()))

		# labels
		tk.Label(parent, text = 'Search Accounts', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'You may leave the field blank if\nyou want a list of all accounts.').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 15))

		tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.').grid(row = 2, columnspan = 2, padx = 30, pady = (0, 30))

		tk.Label(parent, text = 'Search Term', font = subtitlefont).grid(row = 3, column = 0, padx = 30, pady = 15)

		# entries
		search_entry = tk.Entry(parent)
		search_entry.grid(row = 3, column = 1, padx = 30, pady = 15)
		search_entry.focus()

		# buttons
		tk.Button(parent, text = 'Search', height = 2, width = 20, command = lambda : self.search_password(search_entry.get())).grid(row = 4, columnspan = 2, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	# 'Search' button event
	def search_password(self, item):

		# obtain all rows which contain 'item', which is the search term
		with open('keys.csv') as password_file:
			row = password_file.readline().strip()
			while row != '':
				if item.lower() in row[: row.rfind(',')].lower():
					self.search_result.append(row)
				row = password_file.readline().strip()

		# if nothing was found, allow the user to search again
		if self.search_result == []:
			mb.showinfo('Nothing Found', 'The search term you entered could not be found.')
			return

		# if something was indeed found, close this window
		# further actions will be taken care of by 'locate_row_of_interest' function
		self.parent.quit()
		self.parent.destroy()

class Found:
	'''
		Display the search results in a window.
		Display all matching items with radio buttons.
		The user must the choose the item of interest.
	'''

	def __init__(self, parent, rows):
		self.parent = parent
		self.rows = rows
		self.row_of_interest = ''
		parent.title('Search Results')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', lambda event : self.get_password_line(var.get()))

		# labels
		tk.Label(parent, text = 'Select an Account', font = titlefont).grid(row = 0, columnspan = 4, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.').grid(row = 1, columnspan = 4, padx = 30, pady = (0, 30))

		# display search results
		var = tk.IntVar(value = 2)
		for index, row in enumerate(rows, 2):
			row = row.split(',')

			# radio buttons
			tk.Radiobutton(parent, variable = var, value = index).grid(row = index, column = 0, padx = (30, 0))

			# labels
			tk.Label(parent, text = row[0]).grid(row = index, column = 1, padx = (0, 15))

			tk.Label(parent, text = row[1]).grid(row = index, column = 2, padx = (0, 15))

			tk.Label(parent, text = row[2]).grid(row = index, column = 3, padx = (0, 30))

		# buttons
		tk.Button(parent, text = 'Select', height = 2, width = 20, command = lambda : self.get_password_line(var.get())).grid(row = index + 1, columnspan = 4, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	# 'Select' button event
	def get_password_line(self, located):
		self.parent.quit()
		self.parent.destroy()
		self.row_of_interest = self.rows[located - 2]

################################################################################

def delete_password(choose_window):
	'''
		Wrapper function to instantiate the DeleteAPassword class.
	'''

	# hide the option choosing window
	choose_window.parent.wm_withdraw()

	# obtain the row containing the password to be deleted
	row_of_interest = locate_row_of_interest(choose_window)

	# if no search was performed
	# or if search was performed but a search result was not chosen, 'None' is obtained
	# in which case, do not delete
	# get out of this function
	if row_of_interest is None:
		choose_window.parent.deiconify()
		return

	deleter = tk.Toplevel(choose_window.parent)
	DeleteAPassword(deleter, row_of_interest)
	deleter.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

class DeleteAPassword:
	'''
		Display the account the user is about to delete from 'keys.csv' file.
		If the user closes the window, do not delete.
		Delete only if the user clicks the 'Delete' button.
	'''

	def __init__(self, parent, row_of_interest):
		self.parent = parent
		self.row_of_interest = row_of_interest
		parent.title('Delete a Password')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', self.remove_pass)

		# obtain credentials
		credentials = row_of_interest.split(',')[: -1]

		# labels
		tk.Label(parent, text = 'Confirm Delete', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Confirm that you want to delete the password\nassociated with this account. This operation is\nirreversible.').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 15))

		tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.').grid(row = 2, columnspan = 2, padx = 30, pady = (0, 30))

		tk.Label(parent, text = 'Account', font = subtitlefont).grid(row = 3, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = credentials[0]).grid(row = 3, column = 1, padx = 30, pady = 15)

		tk.Label(parent, text = 'User ID', font = subtitlefont).grid(row = 4, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = credentials[1]).grid(row = 4, column = 1, padx = 30, pady = 15)

		tk.Label(parent, text = 'User Name', font = subtitlefont).grid(row = 5, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = credentials[2]).grid(row = 5, column = 1, padx = 30, pady = 15)

		# buttons
		tk.Button(parent, text = 'Delete', height = 2, width = 20, command = self.remove_pass).grid(row = 6, columnspan = 2, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	# 'Delete' button event
	def remove_pass(self, event = None):

		# get confirmation
		response = mb.askyesno('Confirmation', 'Delete this password? This process cannot be undone.', icon = 'warning')
		if response == False:
			return

		# write all other passwords to new file
		with open('keys.csv') as password_file:
			row = password_file.readline().strip()
			with open('.keys', 'w') as updated_password_file:
				while row != '':
					if row != self.row_of_interest:
						updated_password_file.write('%s\n' % row)
					row = password_file.readline().strip()

		# clean up
		os.remove('keys.csv')
		os.rename('.keys', 'keys.csv')
		mb.showinfo('Password Deleted', 'The password was deleted successfully.')

		self.parent.quit()
		self.parent.destroy()

################################################################################

def change_password(choose_window):
	'''
		Wrapper function to instantiate the ChangeAPassword class.
	'''

	# hide the option choosing window
	choose_window.parent.wm_withdraw()

	# obtain the row containing the password to be changed
	row_of_interest = locate_row_of_interest(choose_window)

	# if no search was performed
	# or if search was performed but a search result was not chosen, 'None' is obtained
	# in which case, do not change
	# get out of this function
	if row_of_interest is None:
		choose_window.parent.deiconify()
		return

	changer = tk.Toplevel(choose_window.parent)
	ChangeAPassword(changer, choose_window.AES_key, row_of_interest)
	changer.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

class ChangeAPassword:
	'''
		Open a window similar to AddAPassword to update existing account details.
		The first three fields should be filled to start with.
		However, the user is given the option to change those, too.
	'''

	def __init__(self, parent, AES_key, row_of_interest):
		self.parent = parent
		self.AES_key = AES_key
		self.row_of_interest = row_of_interest
		self.labelpassvar = tk.StringVar(value = genpass(18)) # for suggested password button
		self.passwordvar = tk.StringVar() # for password entry
		self.cpasswordvar = tk.StringVar() # for confirm password entry
		parent.title('Change a Password')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', lambda event : self.update_pw(acc_entry.get(), ID_entry.get(), name_entry.get(), pw_entry.get(), cpw_entry.get()))

		# obtain old credentials
		credentials = row_of_interest.split(',')

		# labels
		tk.Label(parent, text = 'Update Credentials', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = (30, 15))

		tk.Label(parent, text = 'Press \'Esc\' to return to the main menu.').grid(row = 1, columnspan = 2, padx = 30, pady = (0, 30))

		tk.Label(parent, text = 'Account', font = subtitlefont).grid(row = 2, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = 'User ID (e.g. email)', font = subtitlefont).grid(row = 3, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = 'User Name', font = subtitlefont).grid(row = 4, column = 0, padx = 30, pady = 15)

		# entries
		acc_entry = tk.Entry(parent, textvariable = tk.StringVar(value = credentials[0]))
		acc_entry.grid(row = 2, column = 1, padx = 30, pady = 15)

		ID_entry = tk.Entry(parent, textvariable = tk.StringVar(value = credentials[1]))
		ID_entry.grid(row = 3, column = 1, padx = 30, pady = 15)

		name_entry = tk.Entry(parent, textvariable = tk.StringVar(value = credentials[2]))
		name_entry.grid(row = 4, column = 1, padx = 30, pady = 15)

		pw_entry = tk.Entry(parent, show = '*', textvariable = self.passwordvar)
		pw_entry.grid(row = 6, column = 1, padx = 30, pady = 15)

		cpw_entry = tk.Entry(parent, show = '*', textvariable = self.cpasswordvar)
		cpw_entry.grid(row = 7, column = 1, padx = 30, pady = 15)

		# buttons
		autofill_button = tk.Button(parent, text = 'Suggested Password', font = subtitlefont, command = self.set_passwords)
		autofill_button.grid(row = 5, column = 0, padx = 30, pady = 15)
		CreateTooltip(autofill_button, 'Auto-fill the password entries\nbelow with the suggested password')

		refresh_button = tk.Button(parent, textvariable = self.labelpassvar, command = self.renew_suggestion, width = 30)
		refresh_button.grid(row = 5, column = 1, padx = 30, pady = 15)
		CreateTooltip(refresh_button, 'Re-generate suggested password')

		pass_button = tk.Button(parent, text = 'Password', font = subtitlefont, command = lambda : show_pass(pw_entry))
		pass_button.grid(row = 6, column = 0, padx = 30, pady = 15)
		CreateTooltip(pass_button, 'Show or hide password')

		cpass_button = tk.Button(parent, text = 'Confirm Password', font = subtitlefont, command = lambda : show_pass(cpw_entry))
		cpass_button.grid(row = 7, column = 0, padx = 30, pady = 15)
		CreateTooltip(cpass_button, 'Show or hide password')

		tk.Button(parent, text = 'Change', height = 2, width = 20, command = lambda : self.update_pw(acc_entry.get(), ID_entry.get(), name_entry.get(), pw_entry.get(), cpw_entry.get())).grid(row = 8, columnspan = 2, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

	# change the suggested password
	def renew_suggestion(self):
		self.labelpassvar.set(genpass(18))

	# 'Suggested Password' button event
	def set_passwords(self):
		self.passwordvar.set(self.labelpassvar.get())
		self.cpasswordvar.set(self.labelpassvar.get())

	# write the new password to a temporary file
	# when done, delete the old file
	def update_pw(self, *credentials):

		# rename the credentials
		account, ID, name, password, confirm_password = credentials

		# check if any field is empty
		if '' in credentials:
			mb.showerror('Empty Input', 'One or more fields are still empty. Fill all of them to proceed.')
			return

		# check if any of 'account', 'ID' or 'name' contains a comma
		if ',' in ''.join(credentials[: 3]):
			mb.showerror('Invalid Input', 'The \'Account\', \'User ID\' and \'User Name\' fields must not contain commas.')
			return

		# check passwords
		if password != confirm_password:
			mb.showerror('Password Mismatch', 'The \'Password\' and \'Confirm Password\' fields do not match.')
			return

		# get confirmation
		response = mb.askyesno('Confirmation', 'Change this password?', icon = 'warning')
		if response == False:
			return

		# read 'keys.csv' for the password to be changed
		with open('keys.csv') as password_file:
			row = password_file.readline().strip()
			with open('.keys', 'w') as updated_password_file:
				while row != '':
					if row != self.row_of_interest:
						updated_password_file.write('%s\n' % row)
					else:
						updated_password_file.write('%s,%s\n' % (','.join(credentials[: 3]), encryptAES(password, self.AES_key)))
					row = password_file.readline().strip()

		# clean up
		os.remove('keys.csv')
		os.rename('.keys', 'keys.csv')
		mb.showinfo('Password Changed', 'The password was changed successfully.')

		self.parent.quit()
		self.parent.destroy()

################################################################################

def view_password(choose_window):
	'''
		Wrapper function to instantiate the ViewAPassword class.
	'''

	# hide the option choosing window
	choose_window.parent.wm_withdraw()

	# obtain the row containing the password to be viewed
	row_of_interest = locate_row_of_interest(choose_window)

	# if no search was performed
	# or if search was performed but a search result was not chosen, 'None' is obtained
	# in which case, do not view
	# get out of this function
	if row_of_interest is None:
		choose_window.parent.deiconify()
		return

	viewer = tk.Toplevel(choose_window.parent)
	ViewAPassword(viewer, choose_window.AES_key, row_of_interest)
	viewer.mainloop()

	# unhide the option choosing window
	choose_window.parent.deiconify()

class ViewAPassword:
	'''
		Display the password in raw form.
	'''

	def __init__(self, parent, AES_key, row_of_interest):
		self.parent = parent
		parent.title('View a Password')
		parent.resizable(0, 0)
		parent.protocol('WM_DELETE_WINDOW', self.close_button)
		parent.bind('<Escape>', self.close_button)
		parent.bind('<Return>', self.close_button)

		# separate the credentials in 'row_of_interest'
		credentials = row_of_interest.split(',')

		# labels
		tk.Label(parent, text = 'View Credentials', font = titlefont).grid(row = 0, columnspan = 2, padx = 30, pady = 30)

		tk.Label(parent, text = 'Account', font = subtitlefont).grid(row = 1, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = credentials[0]).grid(row = 1, column = 1, padx = 30, pady = 15)

		tk.Label(parent, text = 'User ID', font = subtitlefont).grid(row = 2, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = credentials[1]).grid(row = 2, column = 1, padx = 30, pady = 15)

		tk.Label(parent, text = 'User Name', font = subtitlefont).grid(row = 3, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = credentials[2]).grid(row = 3, column = 1, padx = 30, pady = 15)

		tk.Label(parent, text = 'Password', font = subtitlefont).grid(row = 4, column = 0, padx = 30, pady = 15)

		tk.Label(parent, text = decryptAES(credentials[3], AES_key)).grid(row = 4, column = 1, padx = 30, pady = 15)

		# buttons
		tk.Button(parent, text = 'Done', height = 2, width = 20, command = self.close_button).grid(row = 5, columnspan = 2, padx = 30, pady = 30)

	def close_button(self, event = None):
		self.parent.quit()
		self.parent.destroy()

################################################################################

def handle_missing_files(hash_exists, keys_exists):
	'''
		Decide what to do if one or both of the data files 'hash' or 'keys.csv' are missing.
		If both are present, do nothing.
	'''

	# both files are present
	if hash_exists and keys_exists:
		return

	# if 'keys.csv' is missing, create an empty 'keys.csv', irrespective of whether 'hash' exists or not
	if not keys_exists:
		open('keys.csv', 'w').close()

	# phantom window
	# required to show the messagebox without another window popping up
	root = tk.Tk()
	root.wm_withdraw()

	# if 'keys.csv' is not empty, it means it was already present
	# in that case, 'hash' was not present (else, the first condition would have been executed)
	# terminate the program, because without 'hash', the contents of 'keys.csv' cannot be used
	if os.stat('keys.csv').st_size:
		mb.showerror('Missing File', 'The file \'hash\' is missing. It is required to log in to the application. Without it, your password file \'keys.csv\' is unusable.')
		raise SystemExit(1)

	# at this point, 'keys.csv' exists and is empty
	# if 'hash' is missing, create it with the default contents
	if not hash_exists:
		response = mb.askyesno('First Time User?', 'The file \'hash\' is missing. It is required to log in to the application. It will be created with \'root\' as the default passphrase.', icon = 'warning')
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

	# take care of the possibility that 'hash' and 'keys.csv' are missing
	handle_missing_files(os.path.isfile('hash'), os.path.isfile('keys.csv'))

	# ask for passphrase to log in
	master = tk.Tk()
	master_Login = Login(master)
	master.mainloop()

	# logging in closes the above tk.Tk, so another new tk.Tk can be opened
	# this new tk.Tk remains open until the program terminates
	# hence, all further windows are opened as tk.Toplevel
	# see the wrapper function definitions to understand it
	userchoice = tk.Tk()
	Choose(userchoice, master_Login.AES_key)
	userchoice.mainloop()
