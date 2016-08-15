from msvcrt import getch
from cryptography.fernet import Fernet
from time import sleep
import sys, os, hashlib, json, re, random, base64

#File contents: {"user@email.com": ("username", "hashed master password", "salt", "encrypted text")}
#Encrypted text: {"Account": "password"}

password_check = re.compile("^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{8,56}$")

def cls(): os.system("cls")

def generate_salt(length=24):
    alphabet = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM!@#$^&*()"
    return ''.join(random.choice(alphabet) for i in range(length))

class Safe:
    def __init__(self):
        self.current_user = ""
        self.username = ""
        self.raw_data = {}
        self.cipher = None
        
        try:
            with open("safe.lck", "r") as f:
                self.raw_data = json.loads(f.read())
                f.close()
        
        except: self.create_account(first_time=True)

        self.accounts = self.raw_data.keys()
        self.main()

    def dump_to_file(self):
        if not self.current_user == "":
            encrypted = self.cipher.encrypt(json.dumps(self.cur_data).encode("utf-8"))
            self.raw_data[self.current_user][3] = encrypted.decode("utf-8")

            os.system("@echo off & del safe.lck")

            os.system("echo {} > safe.lck".format(json.dumps(self.raw_data)))
    
    def exit(self):
        self.dump_to_file()
        cls()
        print("Exiting...")
        
        sys.exit()

    def input(self, prompt=""):
        try: return input(prompt)
        except: self.exit()
    
    def getch(self, string=False, prompt=""):
        try:
            char = None
            if string:
                string = ""
                stars = ""
                skip_char = False
                while True:
                    cls()
                    print(prompt + stars)
                    raw_char = ord(getch())
                    char = chr(raw_char)

                    if skip_char:
                        skip_char = False
                        continue

                    if char in ("\x00", "\xe0"):
                        skip_char = True
                        continue
                    
                    if raw_char == 3 or raw_char == 17: self.exit() #Crtl + C or Crtl + Q
                    if raw_char == 13: break

                    if raw_char == 8:
                        if not string == "": string = string[0:len(string)-1]
                        if not stars == "": stars = stars[0:len(stars)-1]
                        continue
                    
                    if char.isalnum() or char in " !@#$%^&*()-=_+[]\\{}|;:\'\",./<>?`~":
                        string += char
                        stars += "*"
                
                return string
        
            else:
                validgetchs = range(49, 49 + self.num_items) #Number inputs = number + 49

                while not char in validgetchs:
                    char = ord(getch())
                    if char == 3 or char == 17: self.exit() #Crtl + C or Crtl + Q

                return char - 48

        except KeyboardInterrupt: self.exit()

    def get_valid_password(self, prompt="", double_check=False, attempts=3):
        self.attempts = attempts

        while self.attempts > 0:
            self.attempts -= 1
            password = self.getch(string=True, prompt=prompt)
    
    def main(self):
        cls()
        print("""PYssword safe v0.1.0

1. Login
2. Create account
3. Exit""")

        self.num_items = 3
        char = self.getch()
        
        if char == 1: self.login()
        elif char == 2: self.create_account()
        elif char == 3: self.exit()

        self.main()

    def login(self):
        cls()
        email = self.input("Email address: ")
        
        self.attempts = 3
        while self.attempts > 0:
            password = self.getch(string=True, prompt="Password: ")
            
            if len(password) < 8:
                cls()
                print("Incorrect.")
                sleep(1)
            
            try:
                self.current_user = email
                self.username = self.raw_data[email][0]
                hashed = self.raw_data[email][1]
                salt = self.raw_data[email][2]
                self.cur_data = self.raw_data[email][3].encode("utf-8")

                key = password.encode("utf-8") + salt.encode("utf-8")
                self.cipher = Fernet(base64.urlsafe_b64encode(key[0:32]))
                self.cur_data = self.raw_data[email][3] = json.loads(self.cipher.decrypt(self.cur_data).decode("utf-8"))
                break
                
            except Exception as e:
                self.cipher = None
                self.current_user = ""
                self.username = ""

                cls()
                print("Incorrect.")
                sleep(1)

        if self.username == "": return

        self.user_menu()

    def user_menu(self):
        cls()
        print("""Hello {}

1. Accounts
2. Change master password
3. Logout""".format(self.username))

        self.num_items = 3
        char = self.getch()

        if char == 1: self.display_accounts()
        elif char == 2: self.change_master_password()
        elif char == 3:
            self.dump_to_file()
            return

        self.user_menu()

    def display_accounts(self):
        cls()
        try: self.page
        except: self.page = 1
        
        num_accounts = len(self.cur_data)

        num_groups, excess = divmod(num_accounts, 6)
        num_groups += 1

        text = "Accounts - {}\n\n1. Add account\n".format(self.current_user)
        displayed = [1, 0, 0, 0, 0, 0, 0, 0, 0]

        i = 0
        for x in self.cur_data.keys():
            if i >= (self.page - 1) * 6 and i < self.page * 6:
                for j in range(len(displayed)):
                    if displayed[j] == 0:
                        try:
                            displayed[j] = x
                            text += "{}. {}\n".format(j + 1, x)
                            break
                        except: pass
        
        if not num_groups == 1:
            self.num_items = 9
            if self.page == num_groups:
                text += "{}. Prev page\n{}. Return".format(excess + 2, excess + 3)
            elif self.page == 1:
                text += "8. Next page\n9. Return"
            else:
                text += "8. Prev page\n9. Next page"
        else:
            self.num_items = excess + 2
            text += "{}. Return".format(excess + 2)
            displayed[excess + 1] = 4
        
        print(text)

        char = self.getch() - 1

        if isinstance(displayed[char], str): self.access_account(displayed[char])
        elif displayed[char] == 1: self.add_account()
        elif displayed[char] == 2: self.page += 1
        elif displayed[char] == 3: self.page -= 1
        elif displayed[char] == 4:
            self.dump_to_file()
            return

        self.display_accounts()

    def access_account(self, key: str):
        cls()
        print("""Account: {}
Password: {}

1. Change password
2. Change account name
3. Remove account
4. Return""".format(key, self.cur_data[key]))

        self.num_items = 4
        char = self.getch()

        if char == 1: pass
        elif char == 2: pass
        elif char == 3: pass
        elif char == 4: return

    def add_account(self):
        cls()
        print("1. Return")

        self.items = 1
        char = self.getch()

        if char == 1: return
    
    def create_account(self, first_time=False):
        
        # Email > Begin
        cls()
        if first_time: print("Welcome to PYssword-Safe.\nIt seems as if you have not run this program before, so I'll help you set up a new account.\nFirst, please enter your email address.\n")
        while True:
            email = re.match("^.+[@].+[\.].+$", self.input("Email address: "))
            if email: break
            cls()
            print("Email must follow the form name@provider.extension")

        self.current_user = email.group(0)
        # Email > End

        # Password > Begin
        cls()
        if first_time: print("Next, please enter a password you will remember.\nIt must contain at least one capital letter, a lowercase letter, a number, and one symbol.\nAlso, the password must have somewhere between 8 and 56 characters.\n")
        while True:
            while True:
                password = self.getch(string=True, prompt="Password: ")
                password = password_check.match(password)
                if password: break
                cls()
                print("Password must have at least one capital letter, one lowercase letter, one number, and one symbol.\nValid symbols are: !@#$&*\nPassword must also be between 8 and 56 characters (inclusive).\n")
                sleep(1)
            
            password = password.group(0)

            cls()
            attempts = 3
            while attempts > 0:
                attempts -= 1
                pwd2 = self.getch(string=True, prompt="Type your password again: ")
                pwd2 = password_check.match(pwd2)

                if pwd2:
                    pwd2 = pwd2.group(0)
                    if password == pwd2: break

                cls()
                print("Passwords do not match.\n")
                sleep(1)

            if password == pwd2: break

            cls()
            print("Too many incorrect attempts. Please retype your orginal password.\n")
            sleep(1)
        # Password > End

        # Username > Begin
        cls()
        fallback = self.current_user.split("@")[0]
        
        print("Name: [{}]".format(fallback))
        self.username = self.input()

        if self.username == "": self.username = fallback
        # Username > End

        salt = generate_salt()
        key = password.encode('utf-8') + salt.encode('utf-8')
        hashed_password = hashlib.sha512(key).hexdigest()

        self.raw_data[self.current_user] = [self.username, hashed_password, salt, {}]
        self.cur_data = self.raw_data[self.current_user][3]
        self.cur_data["Example account"] = "Example password"

        self.cipher = Fernet(base64.urlsafe_b64encode(key[0:32])) #Using the first 32 characters of the password + salt (as utf-8), converted to base 64
        
        self.exit()

Safe()
