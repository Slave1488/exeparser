import argparse
from exeparser import parse

argparser = argparse.ArgumentParser()

argparser.add_argument('source')


if __name__ == '__main__':
    args = argparser.parse_args()
    with open(args.source, 'br') as exe:
        parse(exe)
        print(exe.tell())
