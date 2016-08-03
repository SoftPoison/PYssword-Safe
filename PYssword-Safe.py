from msvcrt import getch
import sys, os, hashlib, json, re
from email.utils import parseaddr

#File contents: {"user@email.com": ("hashed master password", "encrypted text")}

def cls(): os.system("cls")

class Safe:
    def __init__(self):
        self.info = "Welcome to PYssword Safe"
        self.current_user = ""
        self.username = ""
        self._raw_data = {}
        
        try:
            with open("safe.lck", "r") as f:
                self._raw_data = json.dumps(f.read())
                f.close()
        
        except: self._create_account()

        self.accounts = self._raw_data.keys()

    def _exit(self):
        if not self.current_user == "":
            pass
        
        sys.exit()
    
    def _input(self, password=False):
        char = None
        if password:
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
            valid_inputs = range(49, 49 + self.num_items) #Number inputs = number + 49

            while not char in valid_inputs:
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
        char = self._input()
        
        if char == 0: self._login()
        elif char == 1: self._create_account()

        self._exit()

    def _login(self):
        cls()
        attempts = 3
        while attempts > 0:
            attempts -= 1
            email = input("Email address: ")
        
        attempts = 3
        while attempts > 0:
            attempts -= 1
            print("Password: ", end='')
            password = self._getch(True)

    def _create_account(self):
        cls()
        while True:
            _, email = parseaddr(input("Email address: "))
            if not email == "": break
            print("Email must follow the form name@provider.extension")
        
        cls()
        while True:
            print("Password:")
            password = self._input(True)
            password = re.match("^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{8,}$", password)
            if password: break
            print("Password must have at least one capital letter, one number, and one symbol.\nValid symbols are: !@#$&*")

        password = password.group(0)
        print(password)
            
        self._exit()

Safe()
