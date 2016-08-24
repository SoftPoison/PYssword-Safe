#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#
#     Author: Tomais Williamson     #
#       Title: PYssword-Safe        #
#                                   #
# Copyright Tomais Williamson, 2016 #
#        All rights reserved        #
#=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=#

#=== Imports ===#
from msvcrt import getch
from cryptography.fernet import Fernet
import sys, os, hashlib, json, re, random, base64

#=== Planned file storage ===#
#File contents: {"user@email.com": ("username", "hashed master password", "salt", "encrypted text")}
#Encrypted text: {"Account": "password"}

#=== Global variables ===#
password_check = re.compile("^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{8,56}$")
"""Explanation of this regex pattern:

^: Match from the beginning of the string
(?=.*[A-Z]): Look ahead and match at least one character of the set [A-Z]
(?=.*[!@#$&*]): Look ahead and match at least one character of the following characters: !@#$&*
(?=.*[0-9]): Look ahead and match at least one number
(?=.*[a-z]): Look ahead and match at least one character of the set [a-z]
.{8,56}: Match between 8 and 56 characters (inclusive)
$: Match until the end of the string
"""

#=== Misc functions ===#
def cls(): os.system("cls") #Just runs clear screen in command prompt as that is the medium that it should be run in

def generate_salt(length=24): #Length has a default value of 24 which can be changed when called
    alphabet = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM!@#$^&*()" #Character set to choose from
    return ''.join(random.choice(alphabet) for i in range(length)) #Returns a string of random characters of <length> length

#=== Main program ===#
class Safe:
    def __init__(self):
        #Initialise variables just in order to prevent any errors
        self.current_user = "" #Email address / dictionary key
        self.username = "" #Name to address users by
        self.raw_data = {} #Raw data from file
        self.cipher = None #Instance of cipher for encryption / decryption purposes

        try: #If the file is not found / cannot be loaded assume it is a first time run
            with open("safe.lck", "r") as f:
                self.raw_data = json.loads(f.read())
                f.close()

        except: self.create_master_account(first_time=True)

        self.main() #Run the main menu

    def dump_to_file(self):
        if not self.current_user == "": #Only run if a user is logged in
            encrypted = self.cipher.encrypt(json.dumps(self.cur_data).encode("utf-8")) #Using the cipher, encrypt a utf-8 encoded string representation of the current data
            self.raw_data[self.current_user][3] = encrypted.decode("utf-8") #Update the main dictionary with the encrypted data

            os.system("erase /Q safe.lck") #Attempt to delete the old file

            os.system("echo {} > safe.lck".format(json.dumps(self.raw_data))) #Write data to the new file

    def exit(self):
        self.dump_to_file() #Attempt to dump data to file
        cls()
        print("Exiting...")

        sys.exit() #Kill the process

    def input(self, prompt=""): #Rehash of input that also listens for keyboard interrupts and EOF errors
        try: return input(prompt)
        except: self.exit()

    def pause(self):
        try: self.input("Press enter to continue.\n") #Try / except statements can be a bit finicky, so attempt to catch uncaught errors
        except: self.exit()

    def getch(self, string=False, prompt=""): #GET CHaracter for getting raw keyboard presses. Also used for silent inputs (passwords, etc)
        try: #One big try / except statement in order to catch uncaught keyboard interrupts
            char = None #Initialise char as None to avoid errors
            if string: #If a string is wanted instead of 1-9
                chars = "" #Initialise variables
                stars = ""
                skip_char = False #Used for weirdness with function keys
                while True:
                    cls()
                    print(prompt + stars) #Stars / asterisks just make it look cooler
                    raw_char = ord(getch()) #Get keyboard input and acutally make it usable
                    char = chr(raw_char) #Convert the character now to save having to convert multiple times

                    if skip_char: #Skip the character if required by previous iteration
                        skip_char = False
                        continue

                    if char in ("\x00", "\xe0"): #If one of these characters are present, the next iteration of the loop will give weird values, hence the need to skip them
                        skip_char = True
                        continue

                    if raw_char == 3 or raw_char == 17: self.exit() #Crtl + C or Crtl + Q
                    if raw_char == 13: break #Enter

                    if raw_char == 8: #Backspace
                        if not chars == "": chars = chars[0:len(chars)-1]
                        if not stars == "": stars = stars[0:len(stars)-1]
                        continue

                    if char.isalnum() or char in " !@#$%^&*()-=_+[]\\{}|;:\'\",./<>?`~": #Check for a valid character
                        chars += char
                        stars += "*"

                return chars

            else: #Single character input
                validgetchs = range(49, 49 + self.num_items) #Generate a list of numbers based on the number of items meant to be in the menu

                while not char in validgetchs: #Loop until valid input is received
                    char = ord(getch())
                    if char == 3 or char == 17: self.exit() #Crtl + C or Crtl + Q

                return char - 48 #Translate to numbers 1 through n from 49 through n + 49

        except KeyboardInterrupt: self.exit()

    def make_password(self, extra_info=None): #Used for getting a valid password to bind to an account
        while True:
            while True:
                prompt = "Remember to choose a strong password.\nA strong password is at least 8 characters long, and contains at least one:\nCapital letter; lowercase letter; number; symbol\n\nValid symbols are: !@#$&*\n"
                if extra_info: prompt = extra_info + "\n" + prompt
                prompt += "\nPassword: "

                password1 = self.getch(string=True, prompt=prompt) #Get a password
                password1 = password_check.match(password1) #Check if the password is valid
                if password1: break #The regex object will return a new object upon a successful match (which equates to True), otherwise it will return None (which equates to False)
                cls()
                print("Password must have at least one capital letter, one lowercase letter, one number, and one symbol.\nValid symbols are: !@#$&*\nPassword must also be between 8 and 56 characters (inclusive).\n")
                self.pause()

            password1 = password1.group(0) #Get the matched string from the object

            cls()
            for i in range(3):
                password2 = self.getch(string=True, prompt="Type your password again: ")

                if password1 == password2: return password1 #Check if the passwords match. If so, return the password

                cls()
                print("Passwords do not match.\n")
                self.pause()

            cls()
            print("Too many incorrect attempts. Please retype your orginal password.\n")
            self.pause()

    def make_simple_password(self, extra_info=None): #Simple passwords: can be of any strength, or can optionally be generated
        password1 = None
        while not password1: #Loop until a valid password
            prompt = "It is recommended (but not necessary) to choose a strong password.\nA strong password is at least 8 characters long, and contains at least one:\nCapital letter; lowercase letter; number; symbol\n\nValid symbols are: !@#$&*\n"
            if extra_info: prompt = extra_info + "\n" + prompt
            prompt += "\nPassword [hit enter to generate a random one]: "

            password1 = self.getch(string=True, prompt=prompt)

            while password1 == None or (isinstance(password1, str) and password1.strip() == ""): #If no password is entered loop until a "strong" password is generated
                password = generate_salt(length=16) #Salts generated are strong enough to be used as passwords
                password = password_check.match(password) #Check the password strength
                if password: return password.group(0) #If it's strong enough, return the password

            if isinstance(password1, str):
                password2 = self.getch(string=True, prompt="Enter your password again: ")
                if password1 != password2: password1 = None
            else: password1 = None

            if not password1:
                print("Passwords do not match.")
                self.pause()

        return password1

    def main(self): #Main menu
        cls()
        print("""PYssword safe v1.0.2

1. Login
2. Create account
3. Exit""")

        self.num_items = 3 #Three items in the menu
        char = self.getch() #Get a character from the user between 1 and 3 (inclusive)

        #Run the function corresponding to the character inputted
        if char == 1: self.login()
        elif char == 2: self.create_master_account()
        elif char == 3: self.exit()

        self.main() #Loop (for when child functions return)

    def login(self):
        cls()
        email = self.input("Email address: ")

        for i in range(3):
            password = self.getch(string=True, prompt="Password: ")

            try: #Attempt to login with the inputted username and password
                self.current_user = email #Initialise all of the variables
                self.username = self.raw_data[email][0] #Exception will be raised here if the email is incorrect
                hashed = self.raw_data[email][1]
                salt = self.raw_data[email][2]
                self.cur_data = self.raw_data[email][3].encode("utf-8")

                key = password.encode("utf-8") + salt.encode("utf-8")
                self.cipher = Fernet(base64.urlsafe_b64encode(key[0:32])) #Exception will be raised in the following line if password is incorrect
                self.cur_data = self.raw_data[email][3] = json.loads(self.cipher.decrypt(self.cur_data).decode("utf-8")) #Attempt to decrypt and decode the data
                break #It will only reach here if both the username and the passwords are correct

            except: #Username / password is incorrect
                self.cipher = None #Reset the variables
                self.current_user = ""
                self.username = ""

                cls()
                print("Incorrect.")
                self.pause()

        if self.username == "": return #Failed login results in the program returning to the main menu

        self.page = 1 #Initialise at first page for use in display_accounts
        self.user_menu() #A successful login would have taken place, so display the user's menu

    def user_menu(self): #Pretty self explanatory if you've looked at the previous comments
        cls()
        print("""Hello {}

1. Accounts
2. Change master password
3. Logout""".format(self.username))

        self.num_items = 3
        char = self.getch()

        if char == 1: self.display_accounts()
        elif char == 2:
            self.change_master_password()
            return
        elif char == 3:
            self.dump_to_file()
            return

        self.user_menu()

    def change_master_password(self):
        cls()
        password = self.make_password() #Get a valid strong password

        salt = generate_salt() #Generate a new salt
        key = password.encode('utf-8') + salt.encode('utf-8') #Get a bytes version of the password + salt
        hashed_password = hashlib.sha512(key).hexdigest() #Hash the key

        self.raw_data[self.current_user] = [self.username, hashed_password, salt, self.cur_data] #Update the data for the current user

        self.cipher = Fernet(base64.urlsafe_b64encode(key[0:32])) #Set the cipher using the first 32 characters of the key

        self.exit()

    def display_accounts(self): #This is where some magic lies
        cls()

        num_accounts = len(self.cur_data) #Get the number of accounts bound to the current user

        num_groups, excess = divmod(num_accounts, 6) #A maximum of 6 accounts can be displayed on each page
        num_groups += 1 #Offset by one in order to display correctly

        text = "Accounts - {}\n\n1. Add account\n".format(self.username) #Will always be at the top of the menu
        displayed = [1, 0, 0, 0, 0, 0, 0, 0, 0] #A table of magic numbers which may also contain strings in order for the program to also "see" the menu

        i = 0
        for x in self.cur_data.keys(): #Iterate through all of the account names
            if i >= (self.page - 1) * 6 and i < self.page * 6: #Only get a maximum of 6 accounts while at the same time not displaying the same account on more than one page
                for j in range(len(displayed)): #Check for a free position in the table
                    if displayed[j] == 0:
                        try: #Catch some random errors
                            displayed[j] = x #Tell the program where in the menu the account lies
                            text += "{}. {}\n".format(j + 1, x) #Also tell the user because that's kinda important
                            break
                        except: pass #If any are caught, just keep iterating
            i += 1 #Can't forget to increase i by 1

        if not num_groups == 1: #if there is more than one group
            self.num_items = 9 #Assume that there are a total of 9 items in the menu
            if self.page == num_groups: #Last accessable page
                self.num_items = excess + 3 #Go back on the assumption
                text += "{}. Prev page\n{}. Return".format(excess + 2, excess + 3)
                displayed[excess + 1] = 3 #More magic numbers for the table
                displayed[excess + 2] = 4
            elif self.page == 1: #First page
                text += "8. Next page\n9. Return"
                displayed[7] = 2
                displayed[8] = 4
            else: #Some other page
                text += "8. Prev page\n9. Next page"
                displayed[7] = 3
                displayed[8] = 2
        else: #Or if there is only one page total, do some magic with variables
            self.num_items = excess + 2
            text += "{}. Return".format(excess + 2)
            displayed[excess + 1] = 4

        print(text) #Finally print the final version of the menu
        #And get the keyboard input which will relate to an object in the table
        char = self.getch() - 1 #Indices in tables start at 0, so the input should too

        if isinstance(displayed[char], str): self.access_account(displayed[char]) #If the selected object is a string (in other words an account name), access the corresponding account
        elif displayed[char] == 1: self.add_account()
        elif displayed[char] == 2: self.page += 1 #Go forward a page
        elif displayed[char] == 3: self.page -= 1 #Go back a page
        elif displayed[char] == 4: #Save the buffer
            self.dump_to_file()
            return

        self.display_accounts() #Loop

    def access_account(self, key: str):
        cls()
        print("""Account: {}
Password: {}

1. Copy password to clipboard
2. Change password
3. Change account name
4. Remove account
5. Return""".format(key, self.cur_data[key]))

        self.num_items = 5
        char = self.getch()

        if char == 1:
            os.system("set pwd=\"{}\" && echo %pwd:~1,-2%|clip && set pwd=".format(self.cur_data[key].replace("^", "^^"))) #Copy the password to the clipboard
            cls()
            self.input("Password copied to clipboard.\nPress enter to clear clipboard and continue\n")
            os.system("type nul | clip") #Then empty the clipboard
        elif char == 2:
            cls()
            self.cur_data[key] = self.make_simple_password()
        elif char == 3:
            cls()
            new_key = self.input("New account name: ")
            if new_key in self.cur_data.keys(): #Check for an existing account of the same name
                print("Error: account name already exists")
                self.pause()
            else: #Grab the password and transfer it to (basically) a new account
                pwd = self.cur_data[key]
                del self.cur_data[key]
                self.cur_data[new_key] = pwd
                return
        elif char == 4:
            cls()
            print("Are you sure?\n\n1. Yes\n2. No")
            self.num_items = 2
            char = self.getch()
            if char == 1:
                del self.cur_data[key] #Delete the account
                return
        elif char == 5: return

        self.access_account(key) #Loop

    def add_account(self):
        cls()
        account_name = None
        while not account_name: #Loop until something is entered
            account_name = self.input("Name of account or website: ")
            if account_name.strip() == "": account_name = None
            if account_name in self.cur_data.keys():
                cls()
                print("Account already exists")
                self.pause()
                return
            cls()

        self.cur_data[account_name] = self.make_simple_password()

    def create_master_account(self, first_time=False):
        cls()
        if first_time: print("Welcome to PYssword-Safe.\nIt seems as if you have not run this program before, so I'll help you set up a new account.\nFirst, please enter your email address.\n")

        while True: #Loop until a real email address is entered
            email = re.match("^.+[@].+[\.].+$", self.input("Email address: ")) #Basically checks for the format name@provider.extension (and yes, I came up with it myself)
            if email: break
            cls()
            print("Email must follow the format name@provider.extension")

        current_user = email.group(0)

        cls()
        info = None
        if first_time: info = "Next, please enter a password you will remember.\n"
        password = self.make_password(extra_info=info) #Get a strong password

        cls()
        fallback = current_user.split("@")[0]

        print("Name that you would like to be addressed by: [or press enter to be called \"{}\"]".format(fallback))
        username = self.input()

        if username == "": username = fallback

        salt = generate_salt() #This has all been addressed previously
        key = password.encode('utf-8') + salt.encode('utf-8')
        hashed_password = hashlib.sha512(key).hexdigest()

        self.current_user = current_user
        self.username = username
        self.raw_data[self.current_user] = [self.username, hashed_password, salt, {}]
        self.cur_data = self.raw_data[self.current_user][3]

        self.cipher = Fernet(base64.urlsafe_b64encode(key[0:32])) #Using the first 32 characters of the password + salt (as utf-8), converted to base 64

        self.exit()

Safe()
