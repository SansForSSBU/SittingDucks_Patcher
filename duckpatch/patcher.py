import argparse
import struct

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from keystone import KS_ARCH_X86, KS_MODE_32, Ks

import duckpatch.data as data
from duckpatch.utils import get_hash


class Offset:
    def __init__(self, value: int):
        self.value = value


class FileOffset(Offset):
    def to_runtime_offset(self, exe):
        for idx, thing in enumerate(exe.memMap):
            if idx == 0:
                continue
            prev = exe.memMap[idx - 1]
            if (self.value < thing[1] or idx + 1 == len(exe.memMap)) and (
                self.value > prev[1]
            ):
                return RuntimeOffset(self.value - prev[1] + prev[0])


class RuntimeOffset(Offset):
    pass


class Landmark:
    def __init__(self, landmark_bytes, offset):
        self.landmark_bytes = landmark_bytes
        self.offset = offset

    def to_offset(self, mem):
        offset = mem.find(self.landmark_bytes)
        if offset == -1:
            raise Exception("Could not find memory we expected to find")
        offset += len(self.landmark_bytes)

        if mem.find(self.landmark_bytes, offset) != -1:
            raise Exception(
                "There are multiple possibilities for where to patch! Aborting"
            )
        return Offset(offset + self.offset)


class GameExecutable:
    def _get_mem_map(self, file_path):
        pe = pefile.PE(file_path)
        mem_map = [(0x00400000, 0x0)]
        for section in pe.sections:
            file_offset = section.PointerToRawData
            memory_offset = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
            mem_map.append((memory_offset, file_offset))
        return mem_map

    def __init__(self, path):
        self.memMap = self._get_mem_map(path)
        self.game_ver = data.game_vers[get_hash(path)]
        with open(path, "rb") as f:
            self.mem = bytearray(f.read())

    def write_to(self, path):
        with open(path, "wb") as f:
            f.write(self.mem)


def do_instaload_patch(exe: GameExecutable):
    # Set up keystone and capstone to handle assembly and disassembly
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    # Find the absolute offset of the frame advance function
    frame_advance_call_offset = (
        Landmark(b"\xff\x52\x24\xe8\xe5\xfd\xff\xff", -5).to_offset(exe.mem).value
    )
    frame_advance_call_bytes = exe.mem[
        frame_advance_call_offset : frame_advance_call_offset + 5
    ]
    ret_ptr = FileOffset(frame_advance_call_offset).to_runtime_offset(exe).value
    frame_advance_fn_offset = (
        list(md.disasm(frame_advance_call_bytes, ret_ptr))[0].operands[0].imm
    )

    # Replace the original call to the frame advance function with a jump to the payload
    cave_offset = data.cave_offsets[exe.game_ver]
    hijack_ptr = FileOffset(cave_offset).to_runtime_offset(exe).value
    jmp_to_hijack, _ = ks.asm(f"JMP {hijack_ptr}", addr=ret_ptr)
    exe.mem[
        frame_advance_call_offset : frame_advance_call_offset + len(jmp_to_hijack)
    ] = jmp_to_hijack

    # Construct the payload and insert it into the code cave
    loading_ptr = data.loading_ptrs_hex[exe.game_ver]
    payload_asm = f"""
        pushal
        pushfd
        cmp dword ptr [{loading_ptr:#x}], 0
        .byte 0x0F, 0x85, 0x05, 0x00, 0x00, 0x00
        call {frame_advance_fn_offset:#x}
        popfd
        popal
        jmp {ret_ptr + 5:#x}
    """
    payload, _ = ks.asm(payload_asm, addr=hijack_ptr)
    exe.mem[cave_offset : cave_offset + len(payload)] = payload


def lock_fdelta_mod(exe: GameExecutable, fdelta=0.016666668):
    # The original binary updates fdelta every frame to enforce a variable framerate.
    # We redirect it to unused memory to prevent this.
    fdelta_update_offset = Landmark(b"\x32\xd2\xd9", 1).to_offset(exe.mem).value
    dump_addr = data.dump_addrs[exe.game_ver].to_bytes(4, "little")
    exe.mem[fdelta_update_offset : fdelta_update_offset + 4] = dump_addr

    # We change fdelta initialization value to the desired value
    fdelta_offset = Landmark(b"\x88\x51\x1c\xc7", 5).to_offset(exe.mem).value
    exe.mem[fdelta_offset : fdelta_offset + 4] = struct.pack("<f", fdelta)


def do_ngplus_mod(exe):
    # The original binary uses this code to set all item flags to 0 on new game.
    # We make it write values greater than 0 instead to give the player all the items.
    offset = data.ngplus_offsets[exe.game_ver]
    exe.mem[offset] = 0x20


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

    if args.instaload:
        do_instaload_patch(exe)
    if args.speedfix:
        lock_fdelta_mod(exe)
    if args.newgameplus:
        do_ngplus_mod(exe)

    exe.write_to(args.out_path)


if __name__ == "__main__":
    main()
