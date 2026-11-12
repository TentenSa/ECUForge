#define ROM_SIZE 4k
memory rom { mau = 8; size = ROM_SIZE; type = rom; map (dest=bus:x, dest_offset=0x10000000, size=4k);
}
memory ram { mau = 8; size = 1k; type = ram; map (dest=bus:x, dest_offset=0x20000000, size=1k);
}
section_layout ::linear { group G (ordered, run_addr=mem:ram) { select ".data"; } }
