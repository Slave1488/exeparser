import sys


class Const(object):
    def __init__(self, val=None):
        self.value = val

    def __set__(self, instanse, value):
        raise AttributeError

    def __get__(self, instanse, owner):
        return self.value


sys.modules[__name__] = Const
