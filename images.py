import const
from enum import Enum, auto


class ObjectC:
    def __init__(self, source):
        self.start = source.tell()


class Byte(ObjectC):
    SIZE = const(1)

    def __init__(self, source):
        super().__init__(source)
        self.val = source.read(self.SIZE)

    def __len__(self):
        return Byte.SIZE

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class Word(ObjectC):
    SIZE = const(2 * Byte.SIZE)

    def __init__(self, source):
        super().__init__(source)
        self.val = source.read(self.SIZE)

    def __len__(self):
        return Word.SIZE

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class DWord(ObjectC):
    SIZE = const(2 * Word.SIZE)

    def __init__(self, source):
        super().__init__(source)
        self.val = source.read(self.SIZE)

    def __len__(self):
        return DWord.SIZE

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class ULongLong(ObjectC):
    SIZE = const(2 * DWord.SIZE)

    def __init__(self, source):
        super().__init__(source)
        self.val = source.read(self.SIZE)

    def __len__(self):
        return ULongLong.SIZE

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class DOSHeader(ObjectC):
    def __init__(self, source):
        super().__init__(source)
        self.magic = Word(source)
        self.cblp = Word(source)
        self.cp = Word(source)
        self.crlc = Word(source)
        self.cparhdr = Word(source)
        self.minalloc = Word(source)
        self.maxalloc = Word(source)
        self.ss = Word(source)
        self.sp = Word(source)
        self.csum = Word(source)
        self.ip = Word(source)
        self.cs = Word(source)
        self.lfarlc = Word(source)
        self.ovno = Word(source)
        self.res = [Word(source) for i in range(4)]
        self.oemid = Word(source)
        self.oeminfo = Word(source)
        self.res2 = [Word(source) for i in range(10)]
        self.lfanew = DWord(source)


class DOSStub(ObjectC):
    def __init__(self, source, end=256):
        super().__init__(source)
        self.val = source.read(end - self.start)


class FileHeader(ObjectC):
    def __init__(self, source):
        super().__init__(source)
        self.machine = Word(source)
        self.number_of_sections = Word(source)
        self.time_date_stamp = DWord(source)
        self.pointer_to_symbol_table = DWord(source)
        self.number_of_symbols = DWord(source)
        self.size_of_optional_header = Word(source)
        self.characteristics = Word(source)


class DataDirectory(ObjectC):
    def __init__(self, source):
        super().__init__(source)
        self.virtual_address = DWord(source)
        self.size = DWord(source)


class OptionalHeader(ObjectC):
    IMAGE_ROM_OPTIONAL_HDR_MAGIC = const(0x0107)
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = const(0x010B)
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = const(0x020B)

    class Format(Enum):
        def _generate_next_value_(name, start, count, last_values):
            return name

        PE32 = auto()
        PE32p = auto()

    @property
    def magic(self):
        return self.__magic

    @magic.setter
    def magic(self, val):
        OH = OptionalHeader
        ival = int(val)
        if ival == OH.IMAGE_ROM_OPTIONAL_HDR_MAGIC:
            raise ValueError('OptionalHeader.magic is \
IMAGE_ROM_OPTIONAL_HDR_MAGIC')
        elif (ival == OH.IMAGE_NT_OPTIONAL_HDR32_MAGIC or
              ival == OH.IMAGE_NT_OPTIONAL_HDR64_MAGIC):
            self._format = (
                ival == OH.IMAGE_NT_OPTIONAL_HDR32_MAGIC and OH.Format.PE32 or
                ival == OH.IMAGE_NT_OPTIONAL_HDR64_MAGIC and OH.Format.PE32p)
            self.__magic = val
        else:
            raise ValueError('Unknown OptionalHeader.magic')

    def __init__(self, source):
        super().__init__(source)
        OH = OptionalHeader
        self.magic = Word(source)
        self.major_linker_version = Byte(source)
        self.minor_linker_version = Byte(source)
        self.size_of_code = DWord(source)
        self.size_of_initialized_data = DWord(source)
        self.size_of_uninitialized_data = DWord(source)
        self.address_of_entry_point = DWord(source)
        self.base_of_code = DWord(source)
        self.base_of_data = (
            self._format == OH.Format.PE32 and DWord(source) or None)
        self.image_base = (
            self._format == OH.Format.PE32 and DWord(source) or
            self._format == OH.Format.PE32p and ULongLong(source))
        self.section_alignment = DWord(source)
        self.file_alignment = DWord(source)
        self.major_operating_system_version = Word(source)
        self.minor_operating_system_version = Word(source)
        self.major_image_version = Word(source)
        self.minor_image_version = Word(source)
        self.major_subsystem_version = Word(source)
        self.minor_subsystem_version = Word(source)
        self.win_32_version_value = DWord(source)
        self.size_of_image = DWord(source)
        self.size_of_headers = DWord(source)
        self.check_sum = DWord(source)
        self.subsystem = Word(source)
        self.dll_characteristics = Word(source)
        self.size_of_stack_reserve = (
            self._format == OH.Format.PE32 and DWord(source) or
            self._format == OH.Format.PE32p and ULongLong(source))
        self.size_of_stack_commit = (
            self._format == OH.Format.PE32 and DWord(source) or
            self._format == OH.Format.PE32p and ULongLong(source))
        self.size_of_heap_reserve = (
            self._format == OH.Format.PE32 and DWord(source) or
            self._format == OH.Format.PE32p and ULongLong(source))
        self.size_of_heap_commit = (
            self._format == OH.Format.PE32 and DWord(source) or
            self._format == OH.Format.PE32p and ULongLong(source))
        self.loader_flags = DWord(source)
        self.number_of_rva_and_sizes = DWord(source)
        self.data_directory = [
            DataDirectory(source)
            for i in range(int(self.number_of_rva_and_sizes))]


class NTHeader(ObjectC):
    def __init__(self, source):
        super().__init__(source)
        self.signature = DWord(source)
        self.file_header = FileHeader(source)
        self.optional_header = OptionalHeader(source)


class SectionHeader(ObjectC):
    IMAGE_SIZEOF_SHORT_NAME = const(8)

    @property
    def misc_virtual_size(self):
        return self.misc

    @property
    def misc_physical_address(self):
        return self.misc

    def __init__(self, source):
        super().__init__(source)
        SH = SectionHeader
        self.name = [Byte(source) for i in range(SH.IMAGE_SIZEOF_SHORT_NAME)]
        self.misc = DWord(source)
        self.virtual_address = DWord(source)
        self.size_of_raw_data = DWord(source)
        self.pointer_to_raw_data = DWord(source)
        self.pointer_to_relocations = DWord(source)
        self.pointer_to_linenumbers = DWord(source)
        self.number_of_relocations = Word(source)
        self.number_of_linenumbers = Word(source)
        self.characteristics = DWord(source)


class Header(ObjectC):
    def __init__(self, source):
        super().__init__(source)
        self.dos_header = DOSHeader(source)
        self.dos_stub = DOSStub(source, int(self.dos_header.lfanew))
        self.nt_header = NTHeader(source)
        self.section_headers = [
            SectionHeader(source)
            for i in range(int(self.nt_header.file_header.number_of_sections))]


class Section(ObjectC):
    def to_first_section(source, nt_header):
        source.seek(
            nt_header.optional_header.start +
            int(nt_header.file_header.size_of_optional_header))

    def __init__(self, source, section_header):
        super().__init__(source)
        self.header = section_header
        source.seek(int(section_header.pointer_to_raw_data))
        self.data = source.read(int(section_header.size_of_raw_data))
