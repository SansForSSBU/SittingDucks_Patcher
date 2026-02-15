game_vers = {
    b'\x83t\x1e\x0c\x07\xc4\x19\xaf\x14j\xc9Y\xc1\xe6\x81\\': "EU",
    b'\x0e\xc3G\xb6\xa9nP\xa3\xf6\xbcw\xbfgZ\xb1\x93': "PO",
    b'\xe8\xd8\xfa5\xff\x9f\xecw\x1b\xfd\xfa\x81\xe1\x0c\xf9\x04': "RU",
    b'\xa4KgS\x7f+\xec\x16#\xa7\x9bx\xc7\x12\xae\x1b': "US04",
    b'\xcf2\xa4\x94\x80-\xdb\x0c\xd3S\xac\xa4\xf6D9\x98': "US05"
}

cave_offsets = {
    "EU": 0x1dcd1c,
    "PO": 0x1924a0,
    "RU": 0x1924a0,
    "US04": 0x191970,
    "US05": 0x191970,
}

loading_ptrs_hex = {
    "EU": 0x5c2b9c,
    "PO": 0x5c3bdc,
    "RU": 0x5c3bdc,
    "US04": 0x5c2b9c,
    "US05": 0x5c2b9c
}

dump_addrs = {
    "US05": 0x005c5f00,
    "US04": 0x005c5f00,
    "EU": 0x005ddf00,
    "RU": 0x005c6f00,
    "PO": 0x005c6f00,
}

ngplus_offsets = {
    "EU": 0x93C3E,
    "RU": 0x947DE,
    "PO": 0x947FE,
    "US04": 0x94D3A,
    "US05": 0x94D3A,
}