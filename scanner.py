from pcapfile import savefile
import sys,re,base64
import zlib

import argparse
parser = argparse.ArgumentParser()


parser.add_argument("pcap_path", type=str, action= 'store',
                    help="path to pcap file")
parser.add_argument("-e", "--elf", action="store_const", const=1,
                    help="Finding and filtering ELF binaries")
parser.add_argument("-p", "--pe", action="store_const", const=1,
                    help="Finding and filtering PE binaries")
parser.add_argument("-m", "--macho", action="store_const", const=1,
                    help="Finding and filtering Mach-O binarios")

args = parser.parse_args()

print(args.elf)

print(args.pcap_path)

testcap = open(args.pcap_path, 'rb')

#https://ru.wikipedia.org/wiki/Executable_and_Linkable_Format#%D0%A4%D0%BE%D1%80%D0%BC%D0%B0%D1%82
elf_regexp = r'\x7f\x45\x4c\x46'
#https://en.wikipedia.org/wiki/List_of_file_signatures
macho_regexp = r'(\xfe\xed\xfa\xce|\xfe\xed\xfa\xcf|\xce\xfa\xed\xfe|\xcf\xfa\xed\xfe)'
pe_regexp = r'\x4e\x5a[\x00-\xff]*\x50\x45'

capfile = savefile.load_savefile(testcap, verbose=True)

for x in capfile.packets:
    s = ''.join(chr(y) for y in x.raw())

    if re.search(r'(GET|POST|PUT|HEAD)\ [^ ]*\ HTTP/1\.(1|0)',s,re.MULTILINE):
        #http request


        indexes = re.search(r'(GET|POST|PUT|HEAD)\ [^ ]*\ HTTP/1\.(1|0)',s,re.MULTILINE).span(0)

        #print(s[indexes[1]-1:],base64.b16encode(s.encode()))

        if re.search(r'(\r\n\r\n|\n\n)',s[indexes[1]-1:],re.MULTILINE) :
            #найдено тело запроса
            body_index = re.search(r'(\r\n\r\n|\n\n)',s[indexes[1]-1:],re.MULTILINE).span(0)

            body = s[body_index[1]:]

            if args.elf and re.search(elf_regexp,body,re.MULTILINE):
                print('Package with ELF binary:',capfile.packets.index(x))

            if args.macho and re.search(macho_regexp,body,re.MULTILINE):
                print('Package with Mach-O binary:',capfile.packets.index(x))

            if args.macho and re.search(pe_regexp,body,re.MULTILINE):
                print('Package with PE binary:',capfile.packets.index(x))
    elif re.search(r'HTTP/1\.(1|0)\ \d*\ \w*',s,re.MULTILINE):
        #http response
        indexes = re.search(r'HTTP/1\.(1|0)\ \d*\ \w*',s,re.MULTILINE).span(0)
        if re.search(r'(\r\n\r\n|\n\n)', s[indexes[1] - 1:], re.MULTILINE):
            #найдено тело ответа
            body_index = re.search(r'(\r\n\r\n|\n\n)', s[indexes[1] - 1:], re.MULTILINE).span(0)
            headers = s[indexes[0]:body_index[1]]



            body = s[body_index[1]:]

            if 'Content-Encoding: gzip' in headers:
                #print(s[:1000])
                print(body)
                body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
            if args.elf and re.search(elf_regexp,body,re.MULTILINE):
                print('Package with ELF binary:',capfile.packets.index(x))

            if args.macho and re.search(macho_regexp,body,re.MULTILINE):
                print('Package with Mach-O binary:',capfile.packets.index(x))

            if args.macho and re.search(pe_regexp,body,re.MULTILINE):
                print('Package with PE binary:',capfile.packets.index(x))



