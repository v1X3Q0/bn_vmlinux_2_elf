# bn_vmlinux_2_elf

## Background

Similar to the functionality of [GitHub - marin-m/vmlinux-to-elf: A tool to recover a fully analyzable .ELF from a raw kernel, through extracting the kernel symbol table (kallsyms)](https://github.com/marin-m/vmlinux-to-elf), this library provides the ability to generate an elf from a provided bndb file.

Tools are provided for resolving kallsyms when the addresses are inferred, but for auto analysis it is recommended deferring to tools like the above.

## How it works

simply hit `Plugins->genElfeader`.

## The resulting elf

The methodology for generating that elf has a bunch of shoots and ladders.

```
┌─────────────────────────┐   ┌─────────────────────────┐
│         Raw File        │   │        Elf Header       │
│                         │   │                         │
│                         │   ├─────────────────────────┤
│                         │   │       Program Header    │
│                         │   │                         │
│                         ├──►├─────────────────────────┤
│                         │   │ Raw File/Found Sections │
│                         │   │                         │
│                         │   │ ─────  ──────  ───────  │
│                         │   │                         │
│                         │   │                         │
│                         │   ├─────────────────────────┤
│                         │   │      Symbol Table       │
│                         │   │                         │
│                         │   ├─────────────────────────┤
│                         │   │      String Table       │
│                         │   │                         │
│                         │   ├─────────────────────────┤
└─────────────────────────┘   │     SHString Table      │
                              │                         │
                              ├─────────────────────────┤
                              │     Section Header      │
                              │                         │
                              └─────────────────────────┘
```

### First, create the Elf Header

The elf header generation is relatively simple, if a known text offset is provided then fill our Elf header will be located there.

### Create the Program headers

The program headers used are for whatever segments binary ninja already has recognized. A buffer is added to the beginning of the binary that is page aligned. As this part has no dependence on parts of the headers generated, this part is completed right away.

When we finish it we will write the number of program headers to the elf header member `e_phnum`.

### Count sections and create shstrtab

The three new sections to be created are `strtab`, `shstrtab` and `symtab`. These sections' names will be added to an allocated `gShstrString` that will be the contents of the `shstrtab` section. We won't say where this section is yet, since it will sit after the symbol table and string tables, which haven't been created yet.

We will then fill out data structures for each `elf_section` that will be used for the section header. This array's number of entries is finalized. Then all entries VA and offset are finalized except for the `strtab` and `shstrtab`. On some linux systems, there are .rel.* entries inbetween the `strtab` and `shstrtab`.

### Create the symbol table

Now we will create the symbol table, we can allocate memory for all symbols that are in both the raw and mapped `binaryview`. Each symbol can be filled into the symbol table and then the symbol table can be finalized.

With the finalized symbol table, we can write the length to the saved section header.

#### Create the string table data

While iterating through each symbol table entry, we can create our string table. To do that, we just add the string for each entry and save their offset into the symbol table offset.

### Create the string table

First we have to write the string table address to the saved `strtab` section header.

Now that we have finalized the symbol table, we can create the string table. We just have to allocate it and write the `gStrRaw` to memory. Then the `strtab` is finalized.

Now that we have finalized the string table, we can write the length to the saved `strtab` section header. 

### Writing the shstrtab to memory

First we have to write the new VA nd PA to the `shstrtab`.

Since we already completed the `shstrtab`, we can allocate the memory at the back of the image and write the previously determined contents to the `binaryview`.

### Create the section header

Now that all the sections have been written to disk and finalized, we will write the section headers to the disk.

We will use this opportunity to then fix the elf header entry for `e_shnum` with the total number of section headers written to disk, and the entry of the shstrtab in those section headers to the elf header member `e_shstrndx`. Lastly, we will fill in the offset of the `e_shoff` with the address that we just allocated the seciton header to be at.

# that's all folks!
