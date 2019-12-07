from images import *
import re


def parse(source):
    header = Header(source)
    Section.to_first_section(source, header.nt_header)
    sections = [
        Section(source, section_header)
        for section_header in header.section_headers]
