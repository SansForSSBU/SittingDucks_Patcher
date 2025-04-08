"""
--- INSTRUCTIONS ---
Set game_folder to the path to your game's folder.
Set instant_loading, speed_issue_fix and new_game_plus to True if you want them enabled, False if you don't.
Once you've set everything, run the script. It will automatically create a backup and overwrite overlay.exe.
You should now be able to launch overlay.exe and the mods you've chosen will be active.

NOTE: If using speed issue fix, you must cap the framerate to 60 via an external program such as DxWnd or the game will run incredibly fast.
Make sure the game is actually running at 60FPS
If it's running slower despite you setting the frame limiter in DxWnd, try enabling Kill D3D Vsync in DxWnd.
NOTE: Speedruns must use instant_loading and speed_issue_fix
"""

game_folder = "C:/Users/Joseph/Desktop/Ducks/Sitting Ducks US05"
# MODS
instant_loading = True
speed_issue_fix = True
new_game_plus = False

def do_instaload_patch():
    """
    Instant loading patch.
    This patch inserts a hijack into a place where normally a function which seems to advance a frame would be called.
    If the game is not loading, it just calls the frame advance function as normal.
    If the game is currently loading, it skips the call to the frame advance function.
    This effectively forces the game to load in 1 frame. 
    On modern hardware, this frame still happens so fast you don't even notice.
    I wonder how this would perform on original hardware (a PS2?) 
    Were they making us suffer through 20 second loading screens for no reason?
    """
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

    # Time to patch!
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
    """
    Speed issue fix
    Due to a bizarre quirk with how the game determines how long ago the last frame (fdelta) was which I still don't understand
    the game would run at inconsistent speeds. Usually this was 98-107% of the normal game speed.
    We have seen the game running as fast as 110% of it's normal speed though this was a one-off anomaly.
    This happens when capping FPS at 60 via dxwnd.
    This patch fixes the issue by preventing the game from storing its best guess of how long it's been since the last frame into fdelta
    The game also sets this to 0.033333 in some places (the developers probably forgot to remove these instructions when porting from the PS2 where the intended FPS was 30FPS). This patch nops out the instruction which do that too.
    By a lucky coincidence, fdelta is initialised to 0.016666 (60fps) on startup, so no need to change that :)
    """
    global patched_mem
    find1 = b"\x32\xd2\xd9" 
    find2 = b"\x88\x51\x1c\xc7" 
    x = get_offset_after(mem, find1) - 1
    dump_addrs = {
        "US05": 0x005c5f00,
        "US04": 0x005c5f00,
        "EU": 0x005ddf00,
        "RU": 0x005c6f00,
        "PO": 0x005c6fff,

    }
    dump_addr = dump_addrs[game_ver].to_bytes(4, 'little')
    # Change FSTP which was storing fdelta somewhere it's used to store it in an unused place in memory.
    patched_mem[x+2:x+6] = dump_addr
    # Change the 0.33333 to 0.166666
    y = get_offset_after(mem, find2) - 1
    patched_mem[y+6] = 0x89
    patched_mem[y+7] = 0x88
    patched_mem[y+8] = 0x88
    patched_mem[y+9] = 0x3c

def do_ngplus_mod():
    """
    New game plus mod
    Makes you start the game with all items
    Patches an instruction which was setting whether you had the item at the start of the game to 0.
    It was moving BL (lower part of B register, which is 0 in this case) into the flag.
    I patched it so it moves AH (upper part of A register) in.
    This actually sets whether you have the item to a number greater than 1, which is not normal.
    But any value except 0 counts as having the item, so it works :)
    
    """
    global patched_mem
    offsets = {
        "EU": 0x93C3E,
        "RU": 0x947DE,
        "PO": 0x947FE,
        "US04": 0x94D3A,
        "US05": 0x94D3A,
    }
    offset = offsets[game_ver]
    patched_mem[offset] = 0x20

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

def get_file_hash(path):
    with open(path, "rb") as f:
        return game_vers[hashlib.file_digest(f, "md5").digest()]
import hashlib
JMP_OPCODE = 0xE9
CALL_OPCODE = 0xE8
NOP_OPCODE = 0x90
JMP_INSTRUCTION_LEN = 5
# TODO: Pull mem map out the same way Ghidra does it...
game_vers = {
    b'\x83t\x1e\x0c\x07\xc4\x19\xaf\x14j\xc9Y\xc1\xe6\x81\\': "EU",
    b'\x0e\xc3G\xb6\xa9nP\xa3\xf6\xbcw\xbfgZ\xb1\x93': "PO",
    b'\xe8\xd8\xfa5\xff\x9f\xecw\x1b\xfd\xfa\x81\xe1\x0c\xf9\x04': "RU",
    b'\xa4KgS\x7f+\xec\x16#\xa7\x9bx\xc7\x12\xae\x1b': "US04",
    b'\xcf2\xa4\x94\x80-\xdb\x0c\xd3S\xac\xa4\xf6D9\x98': "US05"
}
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
backup_exe_name = "backup_overlay.exe"
output_exe_name = "overlay.exe"
try:
    with open(f"{game_folder}/{backup_exe_name}", "rb") as f:
        mem = f.read()
        
except FileNotFoundError:
    # This must be the first time we're running, so let's create the backup.
    try:
        with open(f"{game_folder}/{output_exe_name}", "rb") as f:
            mem = f.read()
            
    except FileNotFoundError:
        print(f"Invalid game folder: {game_folder}")
        raise Exception("Bad game folder")
    with open(f"{game_folder}/{backup_exe_name}", "wb") as f:
        f.write(mem)

game_ver = get_file_hash(f"{game_folder}/{backup_exe_name}")
memMap = memMaps[game_ver]
patched_mem = bytearray(mem)

if instant_loading: do_instaload_patch()
if speed_issue_fix: do_speed_issue_fix()
if new_game_plus: do_ngplus_mod()

with open(f"{game_folder}/{output_exe_name}", "wb") as f:
    f.write(patched_mem)
print(f"""Successfully patched game at {game_folder} with mods:
Fast loading: {instant_loading}
Speed issue fix: {speed_issue_fix}
New game plus: {new_game_plus}""")
