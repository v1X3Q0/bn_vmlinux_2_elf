# ki_to_vmlinux

The point of this particular tool is to generate a vmlinux elf file from a provided kernel image. Although some automation is provided, when just operating on a one off kernel a json file can be provided with offsets to needed sections.

| section name        | description                                                                                                                                     | how to find                                                                                                  |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `.head.text`        | In android kernels, and some more modern linux, this usually just contains the address of a branch to `_sinittext`, or the .init.text section.  | This is typically the first section in the address space.                                                    |
| `.init`             | In some older kernels, more traditional linux ones at least, the .init is the address of the stext tymbol. It has some initialization routines. | This is the first section in the address space.                                                              |
| `.text`             | This section has primary code.                                                                                                                  | This section is directly after the .head.text section, or after the .init.                                   |
| `__ksymtab`         |                                                                                                                                                 | typically 0 initialized, but borders the kcrctab and/or ksymtab_strings                                      |
| `__kcrctab`         | This section has the kcrctab crcs. Each crc is typically 4 bytes                                                                                | Tends to surround the                                                                                        |
| `__ksymtab_strings` | This section contains both the ksymtab and the ksymtab_gpl strings.                                                                             | Easiest way I've found this table is looking for the string printk and seeing if function names surround it. |
| `__param`           |                                                                                                                                                 |                                                                                                              |
| `__modver`          |                                                                                                                                                 |                                                                                                              |
| `__ex_table`        |                                                                                                                                                 |                                                                                                              |
| `.init.text`        | This is the modern version of the init section.                                                                                                 | Follow the branch from the `.head.text` section.                                                             |


Then a shorthand sample of the json:

```json
    "sections": {
        ".head.text": {
            "sh_addralign": 4,
            "sh_flags": ${"SHF_EXECINSTR"} | ${"SHF_WRITE"},
            "p_flags": ${"PF_X"} | ${"PF_W"},
            "location": "base_inits"
        },
        ".text": {
            "sh_addralign": 2048,
            "sh_flags": ${"SHF_EXECINSTR"} | ${"SHF_WRITE"},
            "p_flags": ${"PF_X"} | ${"PF_W"},
            "location": "base_inits"
        },
        "__ksymtab": {
            "sh_addralign": 8,
            "sh_flags": ${"SHF_WRITE"},
            "p_flags": ${"PF_W"}
        },
        "__kcrctab": {
            "sh_addralign": 1,
            "sh_flags": ${"SHF_WRITE"},
            "p_flags": ${"PF_W"}
        },
        "__ksymtab_strings": {
            "sh_addralign": 1,
            "sh_flags": ${"SHF_WRITE"},
            "p_flags": ${"PF_W"}
        },
        "__param": {
            "sh_addralign": 8,
            "sh_flags": ${"SHF_WRITE"},
            "p_flags": ${"PF_W"}
        },
        "__modver": {
            "sh_addralign": 8,
            "sh_flags": ${"SHF_WRITE"},
            "p_flags": ${"PF_W"}
        },
        "__ex_table": {
            "sh_addralign": 8,
            "sh_flags": ${"SHF_WRITE"},
            "p_flags": ${"PF_W"}
        },
        ".init.text": {
            "sh_addralign": 8,
            "sh_flags" : ${"SHF_EXECINSTR"} | ${"SHF_WRITE"},
            "p_flags": ${"PF_X"} | ${"PF_W"},
            "location": "base_inits"
        }
    },
    "variables": {

    },
    "heuristics": {
        ""
    }
}
```

Then an old arm kernel readelf -S

```
mariomain@raichu-1:~$ readelf -S /mnt/c/Users/mariomain/Projects/r7000/vmlinux
There are 16 section headers, starting at offset 0x318c9c:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .note.gnu.build-i NOTE            00000000 010000 000024 00   A  0   0  4
  [ 2] .init             PROGBITS        c0008000 018000 01ab0e 00 WAX  0   0 32
  [ 3] .text             PROGBITS        c0023000 033000 2b4ed8 00  AX  0   0 1024
  [ 4] __ksymtab         PROGBITS        c02d8000 2e8000 004a88 00   A  0   0  4
  [ 5] __ksymtab_gpl     PROGBITS        c02dca88 2eca88 0021f8 00   A  0   0  4
  [ 6] __ksymtab_strings PROGBITS        c02dec80 2eec80 00ea05 00   A  0   0  1
  [ 7] __param           PROGBITS        c02ed688 2fd688 000978 00   A  0   0  4
  [ 8] .data             PROGBITS        c02ee000 2fe000 01ab40 00  WA  0   0 32
  [ 9] .data..shared_ali PROGBITS        c0308b40 318b40 000080 00  WA  0   0 32
  [10] .bss              NOBITS          c0308bc0 318bc0 01f50c 00  WA  0   0 32
  [11] .comment          PROGBITS        00000000 318bc0 000024 01  MS  0   0  1
  [12] .ARM.attributes   ARM_ATTRIBUTES  00000000 318be4 000010 00      0   0  1
  [13] .shstrtab         STRTAB          00000000 318bf4 0000a6 00      0   0  1
  [14] .symtab           SYMTAB          00000000 318f1c 09c140 10     15 32890  4
  [15] .strtab           STRTAB          00000000 3b505c 071c08 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  y (purecode), p (processor specific)
```

Automation support
