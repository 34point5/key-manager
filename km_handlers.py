#!/usr/bin/env python3

import hashlib as hl
import os
import random
import string
import tkinter as tk
import tkinter.messagebox as mb

import km_classes

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
	return ''.join(random.choice(2 * letter + digit + punct) for _ in range(n))

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

def restore_focus_to(window, widget = None):
	'''
	Make a window the active window. Additionally, focus on a widget of that window.
	On Windows OS, whenever a message box is closed, its tk.Toplevel or tk.Tk does not become active automatically.
	This function will make 'window' the active window and restore focus to 'widget'.
	Solving this problem is not as straightforward as simply calling 'focus_force' on the window.
	If the user closes the window when its message box was open, the window cannot be made the active window.
	Because it has been closed! In which case, this function should do nothing.

	Args:
		window: window which has to be brought into focus
		widget: a widget within 'window' which will be focused (if provided)

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

def move_to_center_of_screen(win):
	'''
	Place the window 'win' in the centre of the screen.
	Coordinates of top left corner of 'win' will be (X, Y).
	x = (screenwidth - windowwidth) / 2
	y = (screenheight - windowheight) / 2
	Getting 'windowwidth' and 'windowheight' is not trivial.

	winfo_width() = width of 'win' excluding outer frame
	winfo_rootx() = x-coordinate of top left point of 'win'
	winfo_x()     = x-coordinate of top left point of 'win' excluding outer frame
	w_form        = width of this above-mentioned frame
	w             = total effective width of 'win'

	winfo_height() = height of 'win' excluding title bar (top) and outer frame (bottom)
	winfo_rooty()  = y-coordinate of top left point of 'win'
	winfo_y()      = y-coordinate of top left point of 'win' excluding title bar
	h              = total effecive height of 'win'

	The 'geometry' method requires the size of 'win' excluding outer frame along with the coordinates of the top left point of 'win'.

	https://stackoverflow.com/questions/3352918
	'''

	# update and get size of the window without outer frame
	win.update()
	w_req, h_req = win.winfo_width(), win.winfo_height()

	# calculate actual width and height of the window
	w_form = win.winfo_rootx() - win.winfo_x()
	w = w_req + 2 * w_form
	h = h_req + win.winfo_rooty() - win.winfo_y() + w_form

	# place the window in the centre
	# point to note: it appears that this can be used only once
	# if it is called, then 'win' is modified, then this is called again, 'win' does not get recentred
	# hence, if a class uses this, then its child class does not get centred on using this
	# so, before calling this in any base class, check class name
	x = (win.winfo_screenwidth() - w) // 2
	y = (win.winfo_screenheight() - h) // 2
	win.geometry('{}x{}+{}+{}'.format(w_req, h_req, x, y))

################################################################################

def proxy(choose_object, handle_code):
	'''
	Hide the window of 'Choose' class.
	Call the function corresponding to the button clicked in 'Choose'.
	If the user clicked 'Change Passphrase', update the 'key' attribute of 'Choose'.
	Because the AES key, 'key', changes when the passphrase is changed.
	'handlers' is a list of functions, and 'handle_code' is an index.

	Args:
		choose_object: 'Choose' class object (it is used to get 'key', the AES key)
		handle_code: int which indicates which function in the list 'handlers' has to be called

	Returns:
		None
	'''

	# find out which widget had focus before hiding the window
	parent = choose_object.parent
	previously_focused_widget = parent.focus_get()
	parent.withdraw()

	# call the appropriate function, then make the hidden window visible again
	key = choose_object.key
	updated_key = handlers[handle_code](key) # return value is useful only when handle_code == 4
	parent.deiconify()
	restore_focus_to(parent, previously_focused_widget)

	# if the function which was called was 'change_passphrase', the AES key ('key') has to be updated
	# it has been returned by the function in 'updated_key'
	# no function other than 'change_passphrase' returns a value
	if handle_code == 4:
		choose_object.key = updated_key

################################################################################

def add_password(key):
	'''
	Wrapper function to instantiate 'AddPassword' class.

	Args:
		key: AES key used to encrypt password

	Returns:
		None
	'''

	adder = tk.Toplevel()
	adder_object = km_classes.AddPassword(adder, key)
	adder.mainloop()

################################################################################

def change_passphrase(key):
	'''
	Wrapper function to instantiate the 'ChangePassphrase' class.

	Args:
		key: AES key used to decrypt passwords

	Returns:
		None
	'''

	updater = tk.Toplevel()
	updater_object = km_classes.ChangePassphrase(updater, key)
	updater.mainloop()

	# 'key' depends on the passphrase: when passphrase is changed, 'key' must also change
	# send new value of 'key' back to 'proxy' function
	# so that 'key' attribute of 'Choose' class can be updated
	return updater_object.key

################################################################################

def locate_row_of_interest():
	'''
	Helper function to change, delete or view a password.
	Locates which line of 'keys.csv' has to be changed, deleted or viewed.
	Instantiates 'Search' class.

	Args:
		None

	Returns:
		string (a row in 'keys.csv') which the user wants to change, delete or view (if search is performed)
		None (if search is not performed)
	'''

	locate = tk.Toplevel()
	locate_object = km_classes.Search(locate)
	locate.mainloop()

	# find what the user chose
	# if the user did not choose any, this will be an empty string
	chosen_row = locate_object.row_of_interest
	if chosen_row == '':
		return None
	return chosen_row

################################################################################

def change_password(key):
	'''
	Wrapper function to instantiate the 'ChangePassword' class.

	Args:
		key: AES key used to encrypt password

	Returns:
		None
	'''

	row_of_interest = locate_row_of_interest()
	if row_of_interest is None:
		return
	changer = tk.Toplevel()
	changer_object = km_classes.ChangePassword(changer, key, row_of_interest)
	changer.mainloop()

################################################################################

def delete_password(key):
	'''
	Wrapper function to instantiate the 'DeletePassword' class.

	Args:
		key: AES key used to encrypt password (not used in this function)

	Returns:
		None
	'''

	row_of_interest = locate_row_of_interest()
	if row_of_interest is None:
		return
	deleter = tk.Toplevel()
	deleter_object = km_classes.DeletePassword(deleter, row_of_interest)
	deleter.mainloop()

################################################################################

def view_password(key):
	'''
	Wrapper function to instantiate the 'ViewPassword' class.

	Args:
		key: AES key used to decrypt password

	Returns:
		None
	'''

	row_of_interest = locate_row_of_interest()
	if row_of_interest is None:
		return
	response = mb.askyesno('Confirmation', 'Are you sure you want the password to be displayed?', icon = 'warning')
	if response == False:
		return
	viewer = tk.Toplevel()
	viewer_object = km_classes.ViewPassword(viewer, key, row_of_interest)
	viewer.mainloop()

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

# available actions
# this is used in the 'proxy' function
handlers = (add_password,
            delete_password,
            change_password,
            view_password,
            change_passphrase)
