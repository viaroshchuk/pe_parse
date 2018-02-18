import logging
from pe_lib_utils import *
# Here must be functions:
# 1. Parse documented structure (parse_pe)
# 2. Generic structures (data dirs)
# 3. Dumps (exe, dll, json, etc.)


def parse_pe(file_raw):
    logging.basicConfig(format='[%(levelname)s]\t%(message)s', level=logging.INFO)
    logging.info('Started basic parsing PE file...')
    dos_header = pe_dos_header(file_raw)
    logging.info('dos_header parsed well! e_lfanew = ' + hex(dos_header.e_lfanew))
    nt_headers = pe_nt_headers(file_raw, dos_header.e_lfanew)
    logging.info('nt_headers parsed well')
    logging.info('Found %i section headers', nt_headers.file_header.number_of_sections)
    sections_offset = dos_header.e_lfanew + 0x04 + 0x14 \
        + nt_headers.file_header.size_of_optional_header

    section_headers = pe_section_headers(file_raw,
                                         nt_headers.file_header.number_of_sections,
                                         sections_offset)
    logging.info('Section headers parsed well.')
    logging.info('Basic parsing is finished.')
    return image(dos_header, nt_headers, section_headers)
