#!/usr/bin/env python3
import struct, sys 

def read_pe_section(filename: str, section_name: str) -> bytearray:
    pe = None 
    sections = {}
    image_base = None

    def read_u64(x: int) -> int:
        return struct.unpack("<Q", pe[x:x+8])[0]

    def read_u32(x: int) -> int:
        return struct.unpack("<I", pe[x:x+4])[0]

    def read_u16(x: int) -> int:
        return struct.unpack("<H", pe[x:x+2])[0]

    def at_va(va: int, is_rva : bool = False) -> slice:
        rva = va - (image_base if not is_rva else 0)
        for s in sections.values():
            if rva >= s["rva"] and rva < s["rva"] + s["va_size"]:
                return slice(rva - s["rva"] + s["raw_offset"], s["raw_size"] + s["raw_offset"])
        raise ValueError("RVA is out of range")

    with open(filename, "rb") as f:
        pe = f.read()

    nt_header_offset = read_u32(0x3c)
    n_sections = read_u16(nt_header_offset + 0x6)
    n_sections_offset = nt_header_offset + read_u16(nt_header_offset + 0x14) + 0x18 
    image_base = read_u64(nt_header_offset + 0x30)
    sections = {}
    for i in range(n_sections):
        section_start_offset = n_sections_offset + 0x28 * i
        
        name = pe[section_start_offset : section_start_offset + 0x8].rstrip(b"\x00").decode("iso-8859-1")
        va_size = read_u32(section_start_offset + 0x8 )
        rva = read_u32(section_start_offset + 0x0c )
        raw_size = read_u32(section_start_offset + 0x10 )
        raw_offset = read_u32(section_start_offset + 0x14 )

        sections[name] = dict(rva=rva, va_size=va_size, raw_size=raw_size, raw_offset=raw_offset)

    return bytearray(pe[at_va(sections[section_name]["rva"], is_rva = True)])

def decode_payload(data_section: bytearray, key_len: int = 0x14, struct_offset:int = 0x10) -> bytes:
    payload_size = struct.unpack("<I", data_section[struct_offset:struct_offset+4])[0]
    payload_key = data_section[struct_offset+4:struct_offset+4+key_len]
    payload = data_section[struct_offset+4+key_len:struct_offset+4+key_len + payload_size]
    for i in range(len(payload)):
        payload[i] ^= payload_key[i % len(payload_key)]
    return payload 
    

def main():
    if len(sys.argv) != 3:
        print("Usage: ex.py INPUT OUTPUT", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[2], "wb") as f:
        f.write(decode_payload(read_pe_section(sys.argv[1], ".data")))

if __name__ == "__main__":
    main()