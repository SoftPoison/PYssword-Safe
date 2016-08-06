from msvcrt import getch
from cryptography.fernet import Fernet
import sys, os, hashlib, json, re, random, base64

#File contents: {"user@email.com": ("hashed master password", "salt", "encrypted text")}

def cls(): os.system("cls")

def generate_salt(length=24):
    alphabet = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
    return ''.join(random.choice(alphabet) for i in range(length))

class Safe:
    def __init__(self):
        self.info = "Welcome to PYssword Safe"
        self.current_user = ""
        self.username = ""
        self._raw_data = {}
        self.cur_data = {}
        self.cipher = None
        
        try:
            with open("safe.lck", "r") as f:
                self._raw_data = json.dumps(f.read())
                f.close()
        
        except: self._create_account()

        self.accounts = self._raw_data.keys()

    def _exit(self):
        cls()
        print("Exiting...")
        if not self.current_user == "":
            pass
        
        sys.exit()

    def _input(self, prompt=""):
        try: return input(prompt)
        except EOFError: self._exit()
        except KeyboardInterrupt: self._exit()
    
    def _getch(self, string=False):
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
                
                if raw_char == 3 or raw_char == 17: self._exit() #Crtl + C or Crtl + Q
                if raw_char == 13: break

                if raw_char == 8:
                    if not string == "": string = string[0:len(string)-1]
                    continue
                
                if char.isalnum() or char in " !@#$%^&*()-=_+[]\\{}|;:\'\",./<>?`~": string += char
            
            return string
        
        else:
            valid_getchs = range(49, 49 + self.num_items) #Number inputs = number + 49

            while not char in valid_getchs:
                char = ord(getch())
                if char == 3 or char == 17: self._exit() #Crtl + C or Crtl + Q

            return char - 49
    
    def main(self):
        cls()
        print("""PYssword safe v0.0.1
1. Login
2. Create account
3. Exit""")

        self.num_items = 3
        char = self._getch()
        
        if char == 0: self._login()
        elif char == 1: self._create_account()

        self._exit()

    def _login(self):
        cls()
        attempts = 3
        while attempts > 0:
            attempts -= 1
            email = self._input("Email address:\n")
        
        attempts = 3
        while attempts > 0:
            attempts -= 1
            print("Password:")
            password = self._getch(True)
            
    def _create_account(self):
        
        # Email > Begin
        cls()
        while True:
            print("Email address:")
            email = re.match("^.+[@].+[\.].+$", self._input())
            if email: break
            cls()
            print("Email must follow the form name@provider.extension")

        self.current_user = email.group(0)
        # Email > End

        # Password > Begin
        cls()
        while True:
            print("Password:")
            password = self._getch(True)
            password = re.match("^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{8,56}$", password)
            if password: break
            cls()
            print("Password must have at least one capital letter, one number, and one symbol.\nValid symbols are: !@#$&*\nPassword must also be between 8 and 56 characters (inclusive)")

        password = password.group(0)
        # Password > End

        # Username > Begin
        cls()
        fallback = self.current_user.split("@")[0]
        
        print("Name: [{}]".format(fallback))
        self.username = self._input()

        if self.username = "": self.username = fallback
        # Username > End

        
        salt = generate_salt()
        key = password.encode('utf-8') + salt.encode('utf-8')
        hashed_password = hashlib.sha512(key).hexdigest()

        self._raw_data[self.current_user] = [self.username, hashed_password, salt, {}]
        self.cur_data = self._raw_data[self.current_user][2]

        self.cipher = Fernet(base64.urlsafe_b64encode(key[0:32]))
        #http://docs.python-guide.org/en/latest/scenarios/crypto/
        self._exit()

Safe()
