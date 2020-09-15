#!/usr/bin/env python3
from base64 import b64decode
import blacklist  # you don't get to see this :p

"""
Don't worry, if you break out of this one, we have another one underneath so that you won't
wreak any havoc!
"""

def main():
    print("EduPy 3.8.2")
    while True:
        try:
            command = input(">>> ")
            if any([x in command for x in blacklist.BLACKLIST]):
                raise Exception("not allowed!!")

            final_cmd = """
_file = open("sandbox.py", "r")
pos = int(((54 * 8) / 16) * (1/3) - 8) # 1
line = _file.readlines()[pos].strip().split(" ")
package = line[pos] # base64
module = line[-pos] # b64decode
_file.close()
attr = getattr(__import__(package), module) # b64decode
res = __builtins__.__dict__['__import__']('numpy')\n""" + command
            exec(final_cmd)

        except (KeyboardInterrupt, EOFError):
            return 0
        except Exception as e:
            print(f"Exception: {e}")

if __name__ == "__main__":
    exit(main())
