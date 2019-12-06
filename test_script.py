def foo():
    print('foo')
    return 'data'


def bar():
    print('bar')
    return


print(False and foo() or True and bar())
