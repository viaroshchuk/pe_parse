from pe_lib import *


def main():
    file_name = input('Enter file name: ')

    with open(file_name, 'rb') as file:
        file_raw = file.read()

    pe_file = parse_pe(file_raw)
    print(hex(pe_file.image_nt_headers.image_optional_header.image_base))


if __name__ == '__main__':
    main()
