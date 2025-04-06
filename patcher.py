cave_mem = b'\xff\xff\x5b\x81\xc4\x90\x00\x00\x00\xC3'
prev_fn_call_mem = b'\xff\x52\x24\xE8\xE5\xFD\xFF\xFF'
def get_offset_after(mem, string):
    offset = mem.find(string)
    if offset == -1:
        raise Exception("Could not find memory we expected to find")
    offset += len(string)

    if mem.find(string, offset) != -1:
        raise Exception("There are multiple possibilities for where to patch! Aborting")
    return offset
path = "C:/Users/Joseph/Desktop/Ducks/Sitting Ducks EU 2004/original.exe"
with open(path, "rb") as f:
    mem = f.read()

# TODO: Pull mem map out the same way Ghidra does it...
memmap = [
    (0x00400000, 0x00000000),
    (0x00401000, 0x00000400),
    (0x005d9000, 0x001d8400),
    (0x005da000, 0x001d9400),
    (0x005dc000, 0x001db400),
    (0x005dd000, 0x001dc400)
]
JMP_OPCODE = 0xE9
CALL_OPCODE = 0xE8
JMP_INSTRUCTION_LEN = 5
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
def get_objective_offset(location, relative_offset):
    return (location + relative_offset + 5) % 0x100000000

def translate_to_runtime_offset(file_offset):
    for idx, thing in enumerate(memmap):
        if idx == 0: continue
        prev = memmap[idx-1]
        if (file_offset < thing[1] or idx+1 == len(memmap)) and (file_offset > prev[1]):
            return file_offset - prev[1] + prev[0]
def format_bytes(b):
    return ' '.join(r''+hex(letter)[2:] for letter in b)

cave_offset = get_offset_after(mem, cave_mem) + 4
frame_advance_call_offset = get_offset_after(mem, prev_fn_call_mem) - 5
frame_advance_call = mem[frame_advance_call_offset:frame_advance_call_offset+5]
hijack_ptr = translate_to_runtime_offset(cave_offset)
ret_ptr = translate_to_runtime_offset(frame_advance_call_offset)
print("Hijack ptr:", hex(hijack_ptr))
print("Ret ptr:", hex(ret_ptr))
print("File cave offset:", hex(cave_offset))
print("File frame advance call offset:", hex(frame_advance_call_offset))


# Time to patch!
patched_mem = bytearray(mem)
jmp_to_hijack = make_jmp_bytes(ret_ptr, hijack_ptr)
patched_mem[frame_advance_call_offset:frame_advance_call_offset+len(jmp_to_hijack)] = jmp_to_hijack

payload = bytearray(
    b"\x60\x9C\x83\x3D\x9C\x2B\x5C\x00\x00\x0F\x85\x05\x00\x00\x00"
    b"\xE8\x00\x00\x00\x00" # CALL to original routine. Index 15-19.
    b"\x9D\x61"
    b"\xE9\x00\x00\x00\x00" # JMP back to where we hijacked from. Index 22-26.
    )
jmp_back = make_jmp_bytes(hijack_ptr+22, ret_ptr+5)
payload[22:27] = jmp_back
# We need to figure out offset for CALL too.
frame_advance_fn_relative_offset = frame_advance_call[1:]
frame_advance_fn_offset = get_objective_offset(int.from_bytes(frame_advance_fn_relative_offset, "little"), ret_ptr)
call_bytes = make_call_bytes(hijack_ptr + 15, frame_advance_fn_offset)
payload[15:20] = call_bytes
patched_mem[cave_offset:cave_offset+len(payload)] = payload
with open("C:/Users/Joseph/Desktop/Ducks/Sitting Ducks EU 2004/overlay.exe", "wb") as f:
    f.write(patched_mem)
pass