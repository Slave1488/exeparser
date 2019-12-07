import re
import pyperclip

M = re.compile(r'(?<!^).{0}(?=[A-Z])')


def rename(name):
    return M.sub(r'_', name).lower()


while True:
    pyperclip.copy(rename(input()))
