from msvcrt import getch
from cryptography.fernet import Fernet
import sys, os, hashlib, json, re, random, base64

#File contents: {"user@email.com": ("hashed master password", "salt", "encrypted text")}

password_check = re.compile("^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{8,56}$")

def cls(): os.system("cls")

def generate_salt(length=24):
    alphabet = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
    return ''.join(random.choice(alphabet) for i in range(length))

class Safe:
    def __init__(self):
        self.info = "Welcome to PYssword Safe"
        self.current_user = ""
        self.username = ""
        self.raw_data = {}
        self.cipher = None
        
        try:
            with open("safe.lck", "r") as f:
                self.raw_data = json.loads(f.read())
                f.close()
        
        except: self.create_account()

        self.accounts = self.raw_data.keys()
        self.main()

    def exit(self):
        if not self.current_user == "":
            encrypted = self.cipher.encrypt(json.dumps(self.cur_data).encode("utf-8"))
            self.raw_data[self.current_user][3] = encrypted.decode("utf-8")

            os.system("@echo off & del safe.lck")

            os.system("echo {} > safe.lck".format(json.dumps(self.raw_data)))
        
        cls()
        print("Exiting...")
        
        sys.exit()

    def input(self, prompt=""):
        try: return input(prompt)
        except EOFError: self.exit()
        except KeyboardInterrupt: self.exit()
    
    def getch(self, string=False):
        char = None
        if string:
            string = ""
            skip_char = False
            while True:
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
                    continue
                
                if char.isalnum() or char in " !@#$%^&*()-=_+[]\\{}|;:\'\",./<>?`~": string += char
            
            return string
        
        else:
            validgetchs = range(49, 49 + self.num_items) #Number inputs = number + 49

            while not char in validgetchs:
                char = ord(getch())
                if char == 3 or char == 17: self.exit() #Crtl + C or Crtl + Q

            return char - 49
    
    def main(self):
        cls()
        print("""PYssword safe v0.0.1
1. Login
2. Create account
3. Exit""")

        self.num_items = 3
        char = self.getch()
        
        if char == 0: self.login()
        elif char == 1: self.create_account()

        self.exit()

    def login(self):
        cls()
        email = self.input("Email address:\n")
        
        attempts = 3
        while attempts > 0:
            attempts -= 1
            print("Password:")
            password = self.getch(True)
            
    def create_account(self, first_time=False):
        
        # Email > Begin
        cls()
        if first_time: print("Welcome to PYssword-Safe.\nIt seems as if you have not run this program before, so I'll help you set up a new account.\nFirst, please enter your email address.\n")
        while True:
            print("Email address:")
            email = re.match("^.+[@].+[\.].+$", self.input())
            if email: break
            cls()
            print("Email must follow the form name@provider.extension")

        self.current_user = email.group(0)
        # Email > End

        # Password > Begin
        cls()
        while True:
            while True:
                print("Password:")
                password = self.getch(True)
                password = password_check.match(password)
                if password: break
                cls()
                print("Password must have at least one capital letter, one number, and one symbol.\nValid symbols are: !@#$&*\nPassword must also be between 8 and 56 characters (inclusive).\n")
            
            password = password.group(0)

            cls()
            attempts = 3
            while attempts > 0:
                attempts -= 1
                print("Type your password again:")
                pwd2 = self.getch(True)
                pwd2 = password_check.match(pwd2)

                if pwd2:
                    pwd2 = pwd2.group(0)
                    if password == pwd2: break

                cls()
                print("Passwords do not match.\n")

            if password == pwd2: break

            cls()
            print("Too many incorrect attempts. Please retype your orginal password.\n")
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
        #http://docs.python-guide.org/en/latest/scenarios/crypto/
        self.exit()

Safe()
