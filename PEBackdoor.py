import pefile


def code_caves(pe, min_size, pe_path):
    print("Searching for code caves")
    caves = []

    fd = open(pe_path, "rb")
    for section in pe.sections:
        if section.SizeOfRawData < min_size: #Skip sections too small
            continue
        fd.seek(section.PointerToRawData, 0) 
        data = fd.read(section.SizeOfRawData)
        
        cave_size = 0
        pos = 0
        for byte in data:
            if byte == 0x00:
                cave_size += 1
            else:
                if cave_size > min_size:
                    raw_addr = section.PointerToRawData + pos - cave_size 
                    print(f"Cave found at {raw_addr} of size {cave_size} in {section.Name.decode()}")
                cave_size = 0
            pos += 1
            

        print(section.Name.decode())


def testfunction():
    pe_path = "../putty.exe"

    pe = pefile.PE(pe_path)

    original_start = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    print(original_start)
    #pe.write("puddy.exe")
    code_caves(pe, 150, pe_path)




if __name__ == "__main__":
    testfunction()
    print("done!")