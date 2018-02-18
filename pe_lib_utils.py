from collections import namedtuple, OrderedDict
import logging
# Declarative part
image = namedtuple('image',
                   'dos_header, nt_headers, section_headers')

image_dos_header = namedtuple('image_dos_header',
                              'e_magic, e_lfanew')

image_nt_headers = namedtuple('image_nt_headers',
                              'signature, file_header, optional_header')

image_file_header = namedtuple('image_file_header',
                               'machine, number_of_sections, time_date_stamp,'
                               'pointer_to_symbol_table, number_of_symbols,'
                               'size_of_optional_header, characteristics')

image_optional_header32 = namedtuple('image_optional_header',
                                     'magic, major_linker_version, minor_linker_version,'
                                     'size_of_code, size_of_initialized_data,'
                                     'size_of_uninitialized_data, address_of_entry_point,'
                                     'base_of_code, base_of_data, image_base, section_alignment,'
                                     'file_alignment, major_operating_system_version,'
                                     'minor_operating_system_version, major_image_version,'
                                     'minor_image_version, major_subsystem_version,'
                                     'minor_subsystem_version, win32_version_value, size_of_image,'
                                     'size_of_headers, check_sum, subsystem, dll_characteristics,'
                                     'size_of_stack_reverse, size_of_stack_commit,'
                                     'size_of_heap_reverse, size_of_heap_commit, loader_flags,'
                                     'number_of_rva_and_sizes, data_directories')

image_optional_header64 = namedtuple('image_optional_header',
                                     'magic, major_linker_version, minor_linker_version,'
                                     'size_of_code, size_of_initialized_data,'
                                     'size_of_uninitialized_data, address_of_entry_point,'
                                     'base_of_code, image_base, section_alignment,'
                                     'file_alignment, major_operating_system_version,'
                                     'minor_operating_system_version, major_image_version,'
                                     'minor_image_version, major_subsystem_version,'
                                     'minor_subsystem_version, win32_version_value, size_of_image,'
                                     'size_of_headers, check_sum, subsystem, dll_characteristics,'
                                     'size_of_stack_reverse, size_of_stack_commit,'
                                     'size_of_heap_reverse, size_of_heap_commit, loader_flags,'
                                     'number_of_rva_and_sizes, data_directories')

image_data_directory = namedtuple('data_directory', 'virtual_address, size')

image_section_header = namedtuple('image_section_header',
                                  'name, virtual_size, virtual_address, size_of_raw_data,'
                                  'pointer_to_raw_data, pointer_to_relocations,'
                                  'pointer_to_linenumbers, number_of_relocations,'
                                  'number_of_linenumbers, characteristics')


# Imperative part
# For parsing byte, word, dword, qword
def pe_value(file_raw, offset_raw, bytes_number):
    return int.from_bytes(file_raw[offset_raw:offset_raw + bytes_number], byteorder='little')


def pe_byte(file_raw, offset_raw):
    return pe_value(file_raw, offset_raw, 1)


def pe_word(file_raw, offset_raw):
    return pe_value(file_raw, offset_raw, 2)


def pe_dword(file_raw, offset_raw):
    return pe_value(file_raw, offset_raw, 4)


def pe_qword(file_raw, offset_raw):
    return pe_value(file_raw, offset_raw, 8)


def pe_char8(file_raw, offset_raw):
    return ''.join([chr(x) for x in file_raw[offset_raw:offset_raw+8] if x != 0x0])


#  Parses given struct
def parse_all(file_raw, structure, mapping, offset_to_structure):
    return structure(*list(mapping[offset](file_raw, offset_to_structure + offset) for offset in mapping))


def pe_dos_header(file_raw, offset_raw=0x00):
    logging.info('Parsing dos_header...')
    mapping = OrderedDict([
        (0x00, pe_word),  # e_magic
        (0x3c, pe_dword)  # e_lfanew
    ])
    return parse_all(file_raw, image_dos_header, mapping, offset_raw)


def pe_file_header(file_raw, offset_raw):
    mapping = OrderedDict([
        (0x00, pe_word),
        (0x02, pe_word),
        (0x04, pe_dword),
        (0x08, pe_dword),
        (0x0C, pe_dword),
        (0x10, pe_word),
        (0x12, pe_word)
    ])
    return parse_all(file_raw, image_file_header, mapping, offset_raw)


def pe_data_dir(file_raw, offset_raw):
    mapping = OrderedDict([
        (0x00, pe_dword),
        (0x04, pe_dword)
    ])
    logging.info('\tParsing data directory at ' + hex(offset_raw))
    return parse_all(file_raw, image_data_directory, mapping, offset_raw)


def pe_data_directories(file_raw, offset_raw):
    logging.info('Parsing data directories...')
    return [pe_data_dir(file_raw, offset_raw + 0x08*i) for i in range(16)]


def pe_optional_header32(file_raw, offset_raw):
    mapping = OrderedDict([
        (0x00, pe_word),
        (0x02, pe_byte),
        (0x03, pe_byte),
        (0x04, pe_dword),
        (0x08, pe_dword),
        (0x0c, pe_dword),
        (0x10, pe_dword),
        (0x14, pe_dword),
        (0x18, pe_dword),
        (0x1c, pe_dword),
        (0x20, pe_dword),
        (0x24, pe_dword),
        (0x28, pe_word),
        (0x2a, pe_word),
        (0x2c, pe_word),
        (0x2e, pe_word),
        (0x30, pe_word),
        (0x32, pe_word),
        (0x34, pe_dword),
        (0x38, pe_dword),
        (0x3c, pe_dword),
        (0x40, pe_dword),
        (0x44, pe_word),
        (0x46, pe_word),
        (0x48, pe_dword),
        (0x4c, pe_dword),
        (0x50, pe_dword),
        (0x54, pe_dword),
        (0x58, pe_dword),
        (0x5c, pe_dword),
        (0x60, pe_data_directories)
    ])
    logging.info('Parsing PE32 optional_header at ' + hex(offset_raw))
    return parse_all(file_raw, image_optional_header32, mapping, offset_raw)


def pe_optional_header64(file_raw, offset_raw):
    mapping = OrderedDict([
        (0x00, pe_word),
        (0x02, pe_byte),
        (0x03, pe_byte),
        (0x04, pe_dword),
        (0x08, pe_dword),
        (0x0c, pe_dword),
        (0x10, pe_dword),
        (0x14, pe_dword),
        (0x18, pe_qword),
        (0x20, pe_dword),
        (0x24, pe_dword),
        (0x28, pe_word),
        (0x2a, pe_word),
        (0x2c, pe_word),
        (0x2e, pe_word),
        (0x30, pe_word),
        (0x32, pe_word),
        (0x34, pe_dword),
        (0x38, pe_dword),
        (0x3c, pe_dword),
        (0x40, pe_dword),
        (0x44, pe_word),
        (0x46, pe_word),
        (0x48, pe_qword),
        (0x50, pe_qword),
        (0x58, pe_qword),
        (0x60, pe_qword),
        (0x68, pe_dword),
        (0x6c, pe_dword),
        (0x70, pe_data_directories)
    ])
    logging.info('Parsing PE32+'
                 ' optional_header at ' + hex(offset_raw))
    return parse_all(file_raw, image_optional_header64, mapping, offset_raw)


def pe_optional_header(file_raw, offset_raw):
    magic = pe_word(file_raw, offset_raw)
    if magic == 0x010b:
        logging.info('Detected PE format: PE32 (magic=0x010b)')
        return pe_optional_header32
    elif magic == 0x020b:
        logging.info('Detected PE format: PE32 (magic=0x020b)')
        return pe_optional_header64
    else:
        logging.critical('Unknown value in optional_header.magic: ' + hex(magic))
        raise TypeError


def pe_section_header(file_raw, offset_raw):
    mapping = OrderedDict([
        (0x00, pe_char8),
        (0x08, pe_dword),
        (0x0c, pe_dword),
        (0x10, pe_dword),
        (0x14, pe_dword),
        (0x18, pe_dword),
        (0x1c, pe_dword),
        (0x20, pe_word),
        (0x22, pe_word),
        (0x24, pe_dword)
    ])
    logging.info('\tParsing section header at ' + hex(offset_raw))
    return parse_all(file_raw, image_section_header, mapping, offset_raw)


def pe_section_headers(file_raw, number_of_sections, offset_raw):
    logging.info('Parsing section_headers at ' + hex(offset_raw))
    return [pe_section_header(file_raw, offset_raw + 0x28*i) for i in range(number_of_sections)]


def pe_nt_headers(file_raw, e_lfanew):
    mapping = OrderedDict([
        (0x00, pe_dword),
        (0x04, pe_file_header),
        (0x18, pe_optional_header(file_raw, e_lfanew + 0x18))  # pe_optional_header - wrapper to other concrete fetcher
    ])
    logging.info('Parsing nt_headers at ' + hex(e_lfanew))
    return parse_all(file_raw, image_nt_headers, mapping, e_lfanew)


def align_down(value, align):
    return value & ~(align-1)


def align_up(value, align):
    return align_down(value-1, align) + align


def rva_to_raw(image, rva):
    if rva < image.nt_headers.optional_header.size_of_headers:
        return rva

    for sect in image.section_headers:
        if (rva >= sect.virtual_address) and \
                (rva < sect.virtual_address + align_up(sect.virtual_size, image.nt_headers.optional_header.section_alignment)):
            print(hex(rva), 'is in', sect.name)
            return rva - sect.virtual_address + sect.pointer_to_raw_data

    logging.critical("Can't resolve rva " + hex(rva))
    exit(-1)


