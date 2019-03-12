#!/usr/bin/env python3

import os
import tkinter as tk

import km_classes
import km_handlers

################################################################################

if __name__ == '__main__':

	# take care of the possibility of 'hash' or 'keys.csv' being missing
	km_handlers.handle_missing_files(os.path.isfile('hash'), os.path.isfile('keys.csv'))

	# window to enter passphrase
	login = tk.Tk()
	login_object = km_classes.Login(login)
	login.mainloop()

	# window to make a selection
	choose = tk.Tk()
	choose_object = km_classes.Choose(choose, login_object.key)
	choose.mainloop()
