from msvcrt import getch
import sys, os

def char_input(functions: tuple, args: tuple):
    #Example:
    #   functions: (test, login, exit)
    #   args: (("hello"), ("username", "password"), None)

    assert len(functions) == len(args), "Input length not equal"

    char = None
    options = range(49, 49 + len(functions)) #Number inputs = number + 48
    
    while not char in options:
        char = ord(getch())
        if char == 3 or char == 17: sys.exit() #Crtl + C or Crtl + Q
    index = char - 49

    if args[index][0] == None: functions[index]()
    else: functions[index](*args[index])

def hello():
    os.system("cls")
    print("Hello")

print("""Some information

1. Hello
2. Exit""")
char_input((hello, sys.exit), ([None], [None]))
