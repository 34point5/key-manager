# key manager
GUI application to store AES256-encrypted keys on your device.

# Usage
Don't.

## Why?
Your passwords will be loaded in RAM, where they will stay for five minutes or five hours, or god knows how long. Python does not offer the functionality to clear them from RAM. Someone could steal your passwords from the RAM if they wanted to.

# I still want to use it
Create a new directory (folder) in an easily accessible place on your computer.
Place the program file in that location.
'hash' stores the SHA-512 of your passphrase and a hint for the passphrase.
'keys.csv' stores the your passwords after they have been encrypted with AES256.
The 'keys.csv' file provided contains some random passwords as samples.
Do not, under any circumstances, modify 'hash' or 'keys.csv' by hand!
