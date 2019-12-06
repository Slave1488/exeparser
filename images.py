import const


class Byte:
    def __init__(self, source):
        self.val = source.read(1)

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class Word:
    def __init__(self, source):
        self.val = Byte(source).val + Byte(source).val

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class DWord:
    def __init__(self, source):
        self.val = Word(source).val + Word(source).val

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class ULongLong:
    def __init__(self, source):
        self.val = DWord(source).val + DWord(source).val

    def __int__(self):
        return int.from_bytes(self.val, 'little')


class DOSHeader:
    def __init__(self, source):
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


class DOSStub:
    def __init__(self, source, len=192):
        self.val = source.read(len)


class FileHeader:
    def __init__(self, source):
        self.machine = Word(source)
        self.number_of_sections = Word(source)
        self.time_date_stamp = DWord(source)
        self.pointer_to_symbol_table = DWord(source)
        self.number_of_symbols = DWord(source)
        self.size_of_optional_header = Word(source)
        self.characteristics = Word(source)


class DataDirectory:
    def __init__(self, source):
        self.virtual_address = DWord(source)
        self.size = DWord(source)


class OptionalHeader:
    IMAGE_ROM_OPTIONAL_HDR_MAGIC = const(0x0107)
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = const(0x010B)
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = const(0x020B)
    PE32, PE32p = map(const, range(1, 3))

    @property
    def magic(self):
        return self.__magic

    @magic.setter
    def magic(self, val):
        OH = OptionalHeader
        ival = int(val)
        if ival == OH.IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            raise ValueError('OptionalHeader.magic is \
IMAGE_ROM_OPTIONAL_HDR_MAGIC')
        elif (ival == OH.IMAGE_NT_OPTIONAL_HDR32_MAGIC or
              ival == OH.IMAGE_NT_OPTIONAL_HDR64_MAGIC):
            self._format = (
                ival == OH.IMAGE_NT_OPTIONAL_HDR32_MAGIC and OH.PE32 or
                ival == OH.IMAGE_NT_OPTIONAL_HDR64_MAGIC and OH.PE32p)
            self.__magic = val
        else:
            raise ValueError('Unknown OptionalHeader.magic')

    def __init__(self, source):
        OH = OptionalHeader
        self.magic = Word(source)
        self.major_linker_version = Byte(source)
        self.minor_linker_version = Byte(source)
        self.size_of_code = DWord(source)
        self.size_of_initialized_data = DWord(source)
        self.size_of_uninitialized_data = DWord(source)
        self.address_of_entry_point = DWord(source)
        self.base_of_code = DWord(source)
        self.base_of_data = self._format == OH.PE32 and DWord(source) or None
        self.image_base = (
            self._format == OH.PE32 and DWord(source) or
            self._format == OH.PE32p and ULongLong(source))
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
            self._format == OH.PE32 and DWord(source) or
            self._format == OH.PE32p and ULongLong(source))
        self.size_of_stack_commit = (
            self._format == OH.PE32 and DWord(source) or
            self._format == OH.PE32p and ULongLong(source))
        self.size_of_heap_reserve = (
            self._format == OH.PE32 and DWord(source) or
            self._format == OH.PE32p and ULongLong(source))
        self.size_of_heap_commit = (
            self._format == OH.PE32 and DWord(source) or
            self._format == OH.PE32p and ULongLong(source))
        self.loader_flags = DWord(source)
        self.number_of_rva_and_sizes = DWord(source)
        self.data_directory = [
            DataDirectory(source)
            for i in range(int(self.number_of_rva_and_sizes))]


class NTHeader:
    def __init__(self, source):
        self.signature = DWord(source)
        self.file_header = FileHeader(source)
        self.optional_header = OptionalHeader(source)


class Header:
    def __init__(self, source):
        self.dos_header = DOSHeader(source)
        self.dos_stub = DOSStub(
            source, int(self.dos_header.lfanew) - source.tell())
        self.nt_header = NTHeader(source)
