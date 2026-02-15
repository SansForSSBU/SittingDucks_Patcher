import argparse
import pefile
import hashlib
import struct

JMP_OPCODE = 0xE9
CALL_OPCODE = 0xE8
NOP_OPCODE = 0x90
JMP_INSTRUCTION_LEN = 5

class Offset:
    def __init__(self, value: int):
        self.value = value
class FileOffset(Offset):
    pass

class RuntimeOffset(Offset):
    pass

class Landmark:
    def __init__(self, landmark_bytes, offset):
        self.landmark_bytes = landmark_bytes
        self.offset = offset

    def to_offset(self, mem):
        return Offset(get_offset_after(mem, self.landmark_bytes) + self.offset)

class GameExecutable:
    def __init__(self, path):
        self.memMap = pull_mem_map(path)
        self.game_ver = get_file_hash(path)
        with open(path, "rb") as f:
            self.mem = f.read()
            self.patched_mem = bytearray(self.mem)

def do_instaload_patch(exe: GameExecutable):
    cave_offsets = {
        "EU": 0x1dcd1c,
        "PO": 0x1924a0,
        "RU": 0x1924a0,
        "US04": 0x191970,
        "US05": 0x191970,
    }
    frame_advance_call_offset = Landmark(b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF', -5).to_offset(exe.mem).value
    cave_offset = cave_offsets[exe.game_ver]
    frame_advance_call = exe.mem[frame_advance_call_offset:frame_advance_call_offset+5]
    hijack_ptr = translate_to_runtime_offset(cave_offset, exe)
    ret_ptr = translate_to_runtime_offset(frame_advance_call_offset, exe)

    # Time to patch!
    jmp_to_hijack = make_jmp_bytes(ret_ptr, hijack_ptr)
    exe.patched_mem[frame_advance_call_offset:frame_advance_call_offset+len(jmp_to_hijack)] = jmp_to_hijack

    payload = bytearray(
        b"\x60\x9C\x83\x3D"
        b"\x00\x00\x00" # Loading pointer. If 0, we are not loading. Index 4-6.
        b"\x00\x00\x0F\x85\x05\x00\x00\x00"
        b"\xE8\x00\x00\x00\x00" # CALL to original routine. Index 15-19.
        b"\x9D\x61"
        b"\xE9\x00\x00\x00\x00" # JMP back to where we hijacked from. Index 22-26.
        )
    payload[4:7] = get_loading_ptr(exe)
    jmp_back = make_jmp_bytes(hijack_ptr+22, ret_ptr+5)
    payload[22:27] = jmp_back
    # We need to figure out offset for CALL too.
    frame_advance_fn_relative_offset = frame_advance_call[1:]
    frame_advance_fn_offset = get_objective_offset(int.from_bytes(frame_advance_fn_relative_offset, "little"), ret_ptr)
    call_bytes = make_call_bytes(hijack_ptr + 15, frame_advance_fn_offset)
    payload[15:20] = call_bytes
    exe.patched_mem[cave_offset:cave_offset+len(payload)] = payload

def lock_fdelta_mod(exe: GameExecutable, fdelta=0.016666668):
    fdelta_update_landmark = b"\x32\xd2\xd9" 
    fdelta_landmark = b"\x88\x51\x1c\xc7" 
    dump_addrs = {
        "US05": 0x005c5f00,
        "US04": 0x005c5f00,
        "EU": 0x005ddf00,
        "RU": 0x005c6f00,
        "PO": 0x005c6f00,
    }
    dump_addr = dump_addrs[exe.game_ver].to_bytes(4, 'little')

    # Make code which was updating fdelta to enforce the variable framerate instead put fdelta somewhere unused.
    fdelta_update_offset = get_offset_after(exe.mem, fdelta_update_landmark) + 1
    exe.patched_mem[fdelta_update_offset:fdelta_update_offset+4] = dump_addr

    # Change fdelta initialization value to the desired value
    fdelta_offset = get_offset_after(exe.mem, fdelta_landmark) + 5
    exe.patched_mem[fdelta_offset:fdelta_offset+4] = struct.pack('<f', fdelta)

def do_ngplus_mod(exe):
    offsets = {
        "EU": 0x93C3E,
        "RU": 0x947DE,
        "PO": 0x947FE,
        "US04": 0x94D3A,
        "US05": 0x94D3A,
    }
    offset = offsets[exe.game_ver]
    exe.patched_mem[offset] = 0x20

def get_offset_after(mem, string):
    offset = mem.find(string)
    if offset == -1:
        raise Exception("Could not find memory we expected to find")
    offset += len(string)

    if mem.find(string, offset) != -1:
        raise Exception("There are multiple possibilities for where to patch! Aborting")
    return offset

def get_relative_offset(start, dest):
    offset = dest - start - JMP_INSTRUCTION_LEN
    if offset < 0:
        offset += 0x100000000
    return offset

def make_jmp_bytes(start, dest):
    offset = get_relative_offset(start, dest)
    jmp_args = offset.to_bytes(4, 'little')
    instr = bytearray(JMP_OPCODE.to_bytes(1, 'little'))
    instr.extend(bytearray(jmp_args))
    instr = bytes(instr)
    return instr

def make_call_bytes(start, dest):
    offset = get_relative_offset(start, dest)
    call_args = offset.to_bytes(4, 'little')
    instr = bytearray(CALL_OPCODE.to_bytes(1, 'little'))
    instr.extend(bytearray(call_args))
    return instr

def get_loading_ptr(exe):

    if exe.game_ver == "EU":
        return bytearray(b"\x9C\x2B\x5C")
    elif exe.game_ver == "PO" or exe.game_ver == 'RU':
        return bytearray(b"\xDC\x3B\x5C")
    elif exe.game_ver == "US04" or exe.game_ver == "US05":
        return bytearray(b"\x9C\x2B\x5C")
    else:
        raise Exception("Unrecognised game version!")

def get_objective_offset(location, relative_offset):
    return (location + relative_offset + 5) % 0x100000000

def translate_to_runtime_offset(file_offset, exe):
    for idx, thing in enumerate(exe.memMap):
        if idx == 0: continue
        prev = exe.memMap[idx-1]
        if (file_offset < thing[1] or idx+1 == len(exe.memMap)) and (file_offset > prev[1]):
            return file_offset - prev[1] + prev[0]

def format_bytes(b):
    return ' '.join(r''+hex(letter)[2:] for letter in b)

def pull_mem_map(file_path):
    pe = pefile.PE(file_path)
    mem_map = [(0x00400000, 0x0)]
    for section in pe.sections:
        file_offset = section.PointerToRawData
        memory_offset = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        mem_map.append((memory_offset, file_offset))
    return mem_map

game_vers = {
    b'\x83t\x1e\x0c\x07\xc4\x19\xaf\x14j\xc9Y\xc1\xe6\x81\\': "EU",
    b'\x0e\xc3G\xb6\xa9nP\xa3\xf6\xbcw\xbfgZ\xb1\x93': "PO",
    b'\xe8\xd8\xfa5\xff\x9f\xecw\x1b\xfd\xfa\x81\xe1\x0c\xf9\x04': "RU",
    b'\xa4KgS\x7f+\xec\x16#\xa7\x9bx\xc7\x12\xae\x1b': "US04",
    b'\xcf2\xa4\x94\x80-\xdb\x0c\xd3S\xac\xa4\xf6D9\x98': "US05"
}

def get_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.file_digest(f, "md5").digest()

def get_file_hash(file_path):
    return game_vers[get_hash(file_path)]

def parse_CLI():
    parser = argparse.ArgumentParser(description="SittingDucks_Patcher")
    parser.add_argument("in_path", type=str, help="In path")
    parser.add_argument("out_path", type=str, help="Out path")
    parser.add_argument("--instaload", action="store_true", help="Instaload")
    parser.add_argument("--speedfix", action="store_true", help="Speed fix")
    parser.add_argument("--newgameplus", action="store_true", help="New game plus")
    return parser.parse_args()

def main():
    args = parse_CLI()
    exe = GameExecutable(args.in_path)

    if args.instaload: do_instaload_patch(exe)
    if args.speedfix: lock_fdelta_mod(exe)
    if args.newgameplus: do_ngplus_mod(exe)

    with open(args.out_path, "wb") as f:
        f.write(exe.patched_mem)

if __name__ == "__main__":
    main()