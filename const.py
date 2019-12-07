import sys


class Const:
    def __init__(self, val=None):
        self.value = val

    def __get__(self, instanse, owner):
        return self.value

    def __set__(self, instanse, value):
        raise AttributeError


sys.modules[__name__] = Const
