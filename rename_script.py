import re

M = re.compile(r'(?<!^).{0}(?=[A-Z])')


def rename(name):
    return M.sub(r'_', name).lower()


while True:
    print(rename(input()))
