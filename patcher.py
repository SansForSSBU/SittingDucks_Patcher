game_ver = "EU"
game_folder = f"C:/Users/Joseph/Desktop/Ducks/Sitting Ducks EU"
original_exe_name = "original.exe" # Rename overlay.exe to original.exe in your game folder to use this patcher.
output_exe_name = "overlay.exe"

JMP_OPCODE = 0xE9
CALL_OPCODE = 0xE8
NOP_OPCODE = 0x90
JMP_INSTRUCTION_LEN = 5
# TODO: Pull mem map out the same way Ghidra does it...
memMaps = {
    "EU": [
        (0x00400000, 0x00000000),
        (0x00401000, 0x00000400),
        (0x005d9000, 0x001d8400),
        (0x005da000, 0x001d9400),
        (0x005dc000, 0x001db400),
        (0x005dd000, 0x001dc400),
    ],
    "PO":
    [
        (0x00400000, 0x0),
        (0x00401000, 0x1000),
        (0x00593000, 0x193000),
        (0x005ad000, 0x1ad000),
        (0x005da000, 0x1c7000),
        (0x005dd000, 0x1ca000),
    ],
    "RU":
    [
        (0x00400000, 0x0),
        (0x00401000, 0x1000),
        (0x00593000, 0x193000),
        (0x005ad000, 0x1ad000),
        (0x005da000, 0x1c7000),
        (0x005dd000, 0x1ca000),
    ],
    "US04":
    [
        (0x00400000, 0x0),
        (0x00401000, 0x1000),
        (0x00592000, 0x192000),
        (0x005ac000, 0x1ac000),
        (0x005d9000, 0x1c6000),
        (0x005dc000, 0x1c9000)
    ],
    "US05":
    [
        (0x00400000, 0x0),
        (0x00401000, 0x1000),
        (0x00592000, 0x192000),
        (0x005ac000, 0x1ac000),
        (0x005d9000, 0x1c6000),
        (0x005dc000, 0x1c9000)
    ],
}
memMap = memMaps[game_ver]
def do_instaload_patch():
    global patched_mem
    cave_mems = {
        "EU": b'\xff\xff\x5b\x81\xc4\x90\x00\x00\x00\xC3',
        "PO": b'\xb8\xac\xb4\x5a\x00\xe9\x6b\x2d\xff\xff',
        "RU": b'\xb8\xac\xb4\x5a\x00\xe9\x6b\x2d\xff\xff',
        "US04": b'\xff\x25\xa8\x21\x59\x00\xb8\xcc\xa3\x5a\x00\xe9\x8b\x2d\xff\xff',
        "US05": b'\xff\x25\xa8\x21\x59\x00\xb8\xcc\xa3\x5a\x00\xe9\x8b\x2d\xff\xff',
    }
    prev_fn_call_mems = {
        "EU": b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF',
        "PO": b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF',
        "RU": b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF',
        "US04": b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF',
        "US05": b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF',
    }
    cave_mem = cave_mems[game_ver]
    prev_fn_call_mem = prev_fn_call_mems[game_ver]
    
    cave_offset = get_offset_after(mem, cave_mem)
    frame_advance_call_offset = get_offset_after(mem, prev_fn_call_mem) - 5
    frame_advance_call = mem[frame_advance_call_offset:frame_advance_call_offset+5]
    hijack_ptr = translate_to_runtime_offset(cave_offset)
    ret_ptr = translate_to_runtime_offset(frame_advance_call_offset)
    #print("Hijack ptr:", hex(hijack_ptr))
    #print("Ret ptr:", hex(ret_ptr))
    #print("File cave offset:", hex(cave_offset))
    #print("File frame advance call offset:", hex(frame_advance_call_offset))


    # Time to patch!
    patched_mem = bytearray(mem)
    jmp_to_hijack = make_jmp_bytes(ret_ptr, hijack_ptr)
    patched_mem[frame_advance_call_offset:frame_advance_call_offset+len(jmp_to_hijack)] = jmp_to_hijack

    payload = bytearray(
        b"\x60\x9C\x83\x3D"
        b"\x00\x00\x00" # Loading pointer. If 0, we are not loading. Index 4-6.
        b"\x00\x00\x0F\x85\x05\x00\x00\x00"
        b"\xE8\x00\x00\x00\x00" # CALL to original routine. Index 15-19.
        b"\x9D\x61"
        b"\xE9\x00\x00\x00\x00" # JMP back to where we hijacked from. Index 22-26.
        )
    payload[4:7] = get_loading_ptr()
    jmp_back = make_jmp_bytes(hijack_ptr+22, ret_ptr+5)
    payload[22:27] = jmp_back
    # We need to figure out offset for CALL too.
    frame_advance_fn_relative_offset = frame_advance_call[1:]
    frame_advance_fn_offset = get_objective_offset(int.from_bytes(frame_advance_fn_relative_offset, "little"), ret_ptr)
    call_bytes = make_call_bytes(hijack_ptr + 15, frame_advance_fn_offset)
    payload[15:20] = call_bytes
    patched_mem[cave_offset:cave_offset+len(payload)] = payload

def do_speed_issue_fix():
    global patched_mem
    find1 = b"\x32\xd2\xd9" # From d9 idx, 6 total bytes must be nopped out (including d9). This removes an instruction which sets fdelta every frame.
    find2 = b"\x88\x51\x1c\xc7" # From c7 idx, 10 total bytes must be nopped out (including c7). This removes an instruction which sets frame delta to 0.033.
    x = get_offset_after(mem, find1) - 1#mem.find(find1) + len(find1) - 1
    patched_mem[x:x+6] = NOP_OPCODE.to_bytes()*6
    y = get_offset_after(mem, find2) - 1#mem.find(find2) + len(find2) - 1
    patched_mem[y:y+10] = NOP_OPCODE.to_bytes()*10
def get_offset_after(mem, string):
    offset = mem.find(string)
    if offset == -1:
        raise Exception("Could not find memory we expected to find")
    offset += len(string)

    if mem.find(string, offset) != -1:
        raise Exception("There are multiple possibilities for where to patch! Aborting")
    return offset


path = f"{game_folder}/{original_exe_name}"




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
def get_loading_ptr():
    global game_ver
    if game_ver == "EU":
        return bytearray(b"\x9C\x2B\x5C")
    elif game_ver == "PO" or game_ver == 'RU':
        return bytearray(b"\xDC\x3B\x5C")
    elif game_ver == "US04" or game_ver == "US05":
        return bytearray(b"\x9C\x2B\x5C")
    else:
        raise Exception("Unrecognised game version!")
def get_objective_offset(location, relative_offset):
    return (location + relative_offset + 5) % 0x100000000
def translate_to_runtime_offset(file_offset):
    for idx, thing in enumerate(memMap):
        if idx == 0: continue
        prev = memMap[idx-1]
        if (file_offset < thing[1] or idx+1 == len(memMap)) and (file_offset > prev[1]):
            return file_offset - prev[1] + prev[0]
def format_bytes(b):
    return ' '.join(r''+hex(letter)[2:] for letter in b)

with open(path, "rb") as f:
    mem = f.read()

do_instaload_patch()
do_speed_issue_fix()

with open(f"{game_folder}/{output_exe_name}", "wb") as f:
    f.write(patched_mem)
print(f"Successfully patched! Patched game is at {game_folder}/{output_exe_name}")