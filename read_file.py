import sys
import struct

#constant set

ELFMAG = "7f454c46"

ELFCLASSNONE = "00"
ELFCLASS32 = "01"
ELFCLASS64 = "02"

ELFDATANONE = "00"
ELFDATA2LSB = "01"
ELFDATA2MSB = "02"

ELFVERSION = "01"

ELFOSABI_NONE = "00"

def read_elf_header(filename):
	with open(filename, 'rb') as f:
		read_elf_ident(f)
		read_rest(f)

def read_elf_ident(f):
	#magic number		
	data = f.read(4)
	to_print = data.encode("hex")
	if to_print != ELFMAG:
		print "Error: not a ELE file"
		sys.exit(0)
	print "ELF file"
	
	#file class
	data = f.read(1)
	to_print = data.encode("hex")
	if to_print == ELFCLASSNONE:
		print "Class: invalid class"
	elif to_print == ELFCLASS32:
		print "Class: 32-bit"
	elif to_print == ELFCLASS64:
		print "Class: 64-bit"
	else:
		print "Error: corrupted!"
		sys.exit(0)

	#data encoding
	data = f.read(1)
	to_print = data.encode("hex")
	if to_print == ELFDATANONE:
		print "Encoding: invalid encoding"
	elif to_print == ELFDATA2LSB:
		print "Encoding: LSB"
	elif to_print == ELFDATA2MSB:
		print "Encoding: MSB"
	else:
		print "Error: corrupted!"
		sys.exit(0)

	#elf header version
	data = f.read(1)
	to_print = data.encode("hex")
	if to_print != ELFVERSION:
		print "Error: corrupted!"
		sys.exit(0)
	print "Header Version: 01"

	#OS / ABI
	data = f.read(1)
	to_print = data.encode("hex")
	if to_print == ELFOSABI_NONE:
		print "OS/ABI: Unspecified"
	else:
		print "TBA"

	#ABIVERSION
	data = f.read(1)
	print "ABI Version: TBD"
	##TBA

	#padding
	data = f.read(7)

ET_NONE = "0000"
ET_REL = "0001"
ET_EXEC = "0002"
ET_DYN = "0003"
ET_CORE = "0004"

def read_rest(f):
	#type		
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")

	if to_print == ET_NONE:
		print "Type: No file type"
	elif to_print == ET_REL:
		print "Type: Relocatable file"
	elif to_print == ET_EXEC:
		print "Type: Executable file"
	elif to_print == ET_DYN:
		print "Type: Shared object file"
	elif to_print == ET_CORE:
		print "Type: Core file"
	else:
		print "Error: corrupted! (or something not implemented)"
		sys.exit(0)

	#machine	
	data = f.read(2)
	to_print = data.encode("hex")
	print "Machine: " + to_print + " (TBD)"

	#elf version
	data = f.read(4)
	to_print = data.encode("hex")
	if to_print != "01000000":
		print "Error: corrupted!"
		sys.exit(0)
	print "Version: 01"

	#address
	data = f.read(4)

	data_lsb = struct.unpack("<i", data)[0]
	data_msb = struct.pack(">i", data_lsb)

	to_print = data_msb.encode("hex")
	print "Entry address: 0x" + to_print

	#e_phoff
	data = f.read(4)

	data_lsb = struct.unpack("<i", data)[0]
	data_msb = struct.pack(">i", data_lsb)

	to_print = data_msb.encode("hex")
	print "Program header table offset: 0x" + to_print

	#e_shoff
	data = f.read(4)

	data_lsb = struct.unpack("<i", data)[0]
	data_msb = struct.pack(">i", data_lsb)

	to_print = data_msb.encode("hex")
	print "Section header table offset: 0x" + to_print

	#elf flag
	data = f.read(4)
	data_lsb = struct.unpack("<i", data)[0]
	data_msb = struct.pack(">i", data_lsb)

	to_print = data_msb.encode("hex")
	print "Flag: 0x" + to_print

	#e_ehsize
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")
	print "Size of this header: 0x" + to_print	

	#e_phentsize
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")
	print "Size of program headers: 0x" + to_print

	#e_phnum
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")
	print "Number of program headers: 0x" + to_print

	#e_shentsize
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")
	print "Size of section headers: 0x" + to_print

	#e_shnum
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")
	print "Number of section headers: 0x" + to_print
	# some special case unhandle

	#e_shstrndx
	data = f.read(2)
	data_lsb = struct.unpack("<h", data)[0]
	data_msb = struct.pack(">h", data_lsb)	

	to_print = data_msb.encode("hex")
	print "Section header string table index: 0x" + to_print



def main():
	length = len(sys.argv)
	if length != 2:
		print "Error: need more argv"
		sys.exit(0)

	read_elf_header(sys.argv[1])
	
if __name__ == "__main__":
	main()
