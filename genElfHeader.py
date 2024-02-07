from binaryninja.binaryview import BinaryViewType, BinaryView, Endianness
from binaryninja import Symbol, SymbolType, Type
import re
from .getStructMemOff import bn_structRetriever
# from .parseSymFile import parseSymFile
from .pyelf import elfSection, elfShndxEnt, elfSymbol
from .bn_raw_elf_fill.setupTypes import grabLinuxElfTypes

def getEnumName(enumType, enumIndex):
    for i in enumType.members:
        if i.value == enumIndex:
            return i.name
    return None

def getEnumValue(enumType, enumName):
    print(enumType, enumName)
    for i in enumType.members:
        if i.name == enumName:
            return i.value
    return None

def fetchStructMem(targetVar, *args):
    targAddr, netOffset, netSize, enumBool = self.bn_sr.getStructMemOff(targetVar, args)
    retValue = br.read(targAddr + netOffset, netSize)
    return retValue

class vmlinux_raw:
    def __init__(self, bv, br, endianess, bitness, architecture, TEXT_OFFSET=None):
        self.bv = bv
        self.br = br
        self.endianess = endianess
        self.bitness = bitness
        self.architecture = architecture
        self.bn_sr = bn_structRetriever(bv, br)
        self.OG_TEXT_SZ = br.length
        self.CUR_TEXT_SZ = self.OG_TEXT_SZ

        elfbitness = str(self.bv.address_size * 8)
        self.Elf_Head_typeS = "Elf{}_Ehdr".format(elfbitness)
        self.secHeadName = 'Elf{}_Shdr'.format(elfbitness)
        self.ElfPrgm = 'Elf{}_Phdr'.format(elfbitness)
        self.ElfSym = "Elf{}_Sym".format(elfbitness)
        if self.bv.address_size == 4:
            prgmsz = 0x20
            elfsz = 0x34
        elif self.bv.address_size == 8:
            prgmsz = 0x30
            elfsz = 0x40

        self.TEXT_OFFSET = TEXT_OFFSET
        if TEXT_OFFSET == None:
            self.TEXT_OFFSET = len(self.bv.segments) * prgmsz + elfsz
        
        self.gSymList = []
        self.gSecList = []
        self.gShndxRaw = '\x00'
        self.gStrRaw = '\x00'

        self.SH_OFFSET = 0
        self.TEXT_ENTRY = self.bv.start
        TEXT_END = 0

    def padInt(self, targInt, padSz=None):
        if padSz == None:
            padSz = self.bv.address_size
        if (targInt % padSz) != 0:
            paddSec = (padSz - (targInt % padSz))
            targInt = targInt + paddSec
        return targInt


    def patchStructMem(self, targetVar, toWrite, *args):
        targAddr, netOffset, netSize, enumBool = self.bn_sr.getStructMemOff(targetVar, args)
        enumValue = None
        if enumBool == None:
            if (len(toWrite) != netSize):
                print("wrong size?!?!? var {}.{} with len {} and estimate {}".format(targetVar, args, len(toWrite), netSize))
                return -1
        if enumBool != None:
            if isinstance(toWrite, str):
                annotateEnum = toWrite.split(' | ')
                enumValue = 0
                for i in annotateEnum:
                    enumValue = enumValue | getEnumValue(enumBool, i)
            else:
                enumValue = toWrite
            toWrite = int.to_bytes(enumValue, byteorder=self.endianess, length=netSize)
        retValue = self.br.write(targAddr + netOffset, toWrite)
        return retValue

    def phEntry(self, phOff, p_type, offset, virtual_address, physical_address, file_size, memory_size, flags, align):
        self.patchStructMem(phOff, p_type, 'p_type')
        
        netSize = self.bn_sr.getStructMemOff_netSize(phOff, ['p_offset'])
        self.patchStructMem(phOff, int.to_bytes(offset, byteorder=self.endianess, length=netSize), 'p_offset')

        netSize = self.bn_sr.getStructMemOff_netSize(phOff, ['p_vaddr'])
        self.patchStructMem(phOff, int.to_bytes(virtual_address, byteorder=self.endianess, length=netSize), 'p_vaddr')
        
        netSize = self.bn_sr.getStructMemOff_netSize(phOff, ['p_paddr'])
        self.patchStructMem(phOff, int.to_bytes(physical_address, byteorder=self.endianess, length=netSize), 'p_paddr')

        netSize = self.bn_sr.getStructMemOff_netSize(phOff, ['p_filesz'])
        self.patchStructMem(phOff, int.to_bytes(file_size, byteorder=self.endianess, length=netSize), 'p_filesz')

        netSize = self.bn_sr.getStructMemOff_netSize(phOff, ['p_memsz'])
        self.patchStructMem(phOff, int.to_bytes(memory_size, byteorder=self.endianess, length=netSize), 'p_memsz')

        self.patchStructMem(phOff, flags, 'p_flags')

        netSize = self.bn_sr.getStructMemOff_netSize(phOff, ['p_align'])
        self.patchStructMem(phOff, int.to_bytes(align, byteorder=self.endianess, length=netSize), 'p_align')

    def symEntry(self, curVarAccessor, curSym, curTempDataName):
        # name
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_name'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symNameOff, byteorder=self.endianess, length=netSize), 'st_name')
        # value
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_value'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symValue, byteorder=self.endianess, length=netSize), 'st_value')
        # size
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_size'])
        self.patchStructMem(curVarAccessor, int.to_bytes(0, byteorder=self.endianess, length=netSize), 'st_size')
        # info
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_info'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symInfo, byteorder=self.endianess, length=netSize), 'st_info')
        # other
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_other'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symOther, byteorder=self.endianess, length=netSize), 'st_other')
        # shndx
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_shndx'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symShndx, byteorder=self.endianess, length=netSize), 'st_shndx')

    def shEntry(self, curVarAccessor, curSec, secHeadName):
        # name
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_name'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secNameOff, byteorder=self.endianess, length=netSize), 'sh_name')
        # type
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_type'])
        self.patchStructMem(curVarAccessor, curSec.secType, 'sh_type')
        # flags
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_flags'])
        self.patchStructMem(curVarAccessor, curSec.secFlags, 'sh_flags')
        # address
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_addr'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secAddr, byteorder=self.endianess, length=netSize), 'sh_addr')
        # offset
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_offset'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secOffset, byteorder=self.endianess, length=netSize), 'sh_offset')        
        # size
        # print("section {} size {}".format(curSec.secName, hex(curSec.secSize)))
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_size'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secSize, byteorder=self.endianess, length=netSize), 'sh_size')
        # align
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_addralign'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secAlign, byteorder=self.endianess, length=netSize), 'sh_addralign')
        if curSec.secName == '.symtab':
            # link
            netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_link'])
            self.patchStructMem(curVarAccessor, int.to_bytes(len(self.gSecList) - 1, byteorder=self.endianess, length=netSize), 'sh_link')
            # info
            netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_info'])
            self.patchStructMem(curVarAccessor, int.to_bytes(0x807a, byteorder=self.endianess, length=netSize), 'sh_info')
            # entry_size
            netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_entsize'])
            self.patchStructMem(curVarAccessor, int.to_bytes(self.br.get_type_by_name(self.ElfSym).width, byteorder=self.endianess, length=netSize), 'sh_entsize')

    def createHeaderSection(self, initPadding):
        self.br.insert(0, initPadding * '\x00')
        self.CUR_TEXT_SZ += initPadding

    # create the 
    def createSymStrTab(self):
        Elf_SY_typeS = self.br.get_type_by_name(self.ElfSym)
        Elf_SY_typeW = Elf_SY_typeS.width
        self.br.insert(self.CUR_TEXT_SZ, (Elf_SY_typeW * len(self.gSymList)) * "\x00")
        
        curTempDataName = '__elf_symbol_table'
        someVarThingSym = Symbol(SymbolType.DataSymbol, self.CUR_TEXT_SZ, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(self.CUR_TEXT_SZ, Type.array(Elf_SY_typeS, len(self.gSymList)))

        self.CUR_TEXT_SZ += (Elf_SY_typeW * len(self.gSymList))

        symTabIndex = 0

        for curSym in self.gSymList:
            curVarAccessor = "{}[{}]".format(curTempDataName, symTabIndex)
            self.symEntry(curVarAccessor, curSym, curTempDataName)
            symTabIndex += 1
            # break
        
        self.br.insert(self.CUR_TEXT_SZ, self.gStrRaw)

    def createShndx(self):
        shdrName = '.shstrtab'
        shndxOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += shdrName + '\x00'
        
        symTabName = '.symtab'
        symTabOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += symTabName + '\x00'

        strTabName = '.strtab'
        strTabOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += strTabName + '\x00'
        shstrSec = elfSection(shdrName, shndxOffTmp, 'SHT_STRTAB', 0, 0, self.CUR_TEXT_SZ, len(self.gShndxRaw), 0x1)

        textPostStr = self.CUR_TEXT_SZ + len(self.gShndxRaw)
        textPostStr = self.padInt(textPostStr)

        textPostStr = textPostStr + (self.br.get_type_by_name(self.secHeadName).width * (len(self.gSecList) + 3))
        symTabSz = self.br.get_type_by_name(self.ElfSym).width * (len(self.gSymList))

        symSec = elfSection(symTabName, symTabOffTmp, 'SHT_SYMTAB', 0, 0, textPostStr, symTabSz, 0x4)

        testPostSec = textPostStr + symTabSz
        
        strSec = elfSection(shdrName, strTabOffTmp, 'SHT_STRTAB', 0, 0, testPostSec, len(self.gStrRaw), 0x1)

        self.gSecList.append(shstrSec)
        self.gSecList.append(symSec)
        self.gSecList.append(strSec)

        self.br.insert(self.CUR_TEXT_SZ, self.gShndxRaw)
        self.CUR_TEXT_SZ += len(self.gShndxRaw)

    def fillProgramHeader(self, pho):
        Elf_PH_typeS = self.br.get_type_by_name(self.ElfPrgm)
        curTempDataName = "__elf_program_headers"
        someVarThingSym = Symbol(SymbolType.DataSymbol, pho, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(pho, Type.array(Elf_PH_typeS, 1))
        entryIndex = 0
        # this has an entry pointing to the beginning of the section header, so
        self.phEntry('{}[{}]'.format(curTempDataName, entryIndex), "PT_LOAD", self.TEXT_OFFSET,
            self.TEXT_ENTRY, self.TEXT_ENTRY, self.OG_TEXT_SZ, self.OG_TEXT_SZ, "PF_X | PF_W | PF_R",
            0x10000)
        entryIndex += 1
        return entryIndex
    
    # it should be .shstrtab
    # section header
    # symtab
    # strtab
    def fillSectionHeader(self):
        self.createShndx()

        secHeadIndex = 0
        totalSections = len(self.gSecList)
        
        newSz = self.padInt(self.CUR_TEXT_SZ)
        self.br.insert(self.CUR_TEXT_SZ, (newSz - self.CUR_TEXT_SZ) * '\x00')
        self.CUR_TEXT_SZ = newSz

        # if anywhere to use the section header offset, it is right here.
        self.SH_OFFSET = self.CUR_TEXT_SZ

        Elf_SH_typeS = self.br.get_type_by_name(self.secHeadName)
        Elf_SH_typeW = Elf_SH_typeS.width
        self.br.insert(self.CUR_TEXT_SZ, (Elf_SH_typeW * totalSections) * "\x00")
        
        curTempDataName = '__elf_section_headers'
        someVarThingSym = Symbol(SymbolType.DataSymbol, self.CUR_TEXT_SZ, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(self.CUR_TEXT_SZ, Type.array(Elf_SH_typeS, totalSections))

        self.CUR_TEXT_SZ += Elf_SH_typeW * totalSections

        for curSec in self.gSecList:
            curVarAccessor = "{}[{}]".format(curTempDataName, secHeadIndex)
            self.shEntry(curVarAccessor, curSec, self.secHeadName)
            secHeadIndex += 1

        self.createSymStrTab()

    def fillElfHeader(self, symFile=None):
        # print(hex(CUR_TEXT_SZ))
        grabLinuxElfTypes(self.bv)
        self.createHeaderSection(self.TEXT_OFFSET)
        # print(hex(CUR_TEXT_SZ))
        # if symFile != None:
        #     parseSymFile(symFile)
        Elf_Head_typeS = self.bv.get_type_by_name(self.Elf_Head_typeS)
        if Elf_Head_typeS == None:
            print("couldn't find {}".format(self.Elf_Head_typeS))
            return

        curTempDataName = '__elf_header'
        curHeadAddress = 0
        someVarThingSym = Symbol(SymbolType.DataSymbol, curHeadAddress, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(curHeadAddress, Elf_Head_typeS)
        self.patchStructMem(curTempDataName, b"\x7fELF", "e_ident", "signature")
        self.patchStructMem(curTempDataName, b"\x01", "e_ident", "file_class")
        self.patchStructMem(curTempDataName, b"\x01", "e_ident", "encoding")
        self.patchStructMem(curTempDataName, b"\x01", "e_ident", "version")
        self.patchStructMem(curTempDataName, b"\x61", "e_ident", "os")
        self.patchStructMem(curTempDataName, b"\x00", "e_ident", "abi_version")
        self.patchStructMem(curTempDataName, "ET_EXEC", "e_type")
        self.patchStructMem(curTempDataName, "EM_ARM", "e_machine")
        self.patchStructMem(curTempDataName, b"\x01", "e_version")
        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_entry'])
        self.patchStructMem(curTempDataName, int.to_bytes(self.TEXT_ENTRY, byteorder=self.endianess, length=netSize), "e_entry")

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_phoff'])
        pho = Elf_Head_typeS.width
        self.patchStructMem(curTempDataName, int.to_bytes(pho, byteorder=self.endianess, length=netSize), "e_phoff")

        self.patchStructMem(curTempDataName, int.to_bytes(0x00000602, byteorder=self.endianess, length=4), "e_flags")

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_ehsize'])
        self.patchStructMem(curTempDataName, int.to_bytes(pho, byteorder=self.endianess, length=netSize), "e_ehsize")

        phs = self.bv.get_type_by_name(self.ElfPrgm).width
        phs = int.to_bytes(phs, byteorder=self.endianess, length=netSize)
        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_phentsize'])
        self.patchStructMem(curTempDataName, phs, "e_phentsize")

        phoEntries = self.fillProgramHeader(pho)
        
        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_phnum'])
        self.patchStructMem(curTempDataName, int.to_bytes(phoEntries, byteorder=self.endianess, length=netSize), "e_phnum")

        eSym = self.bv.get_type_by_name(self.secHeadName).width
        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shentsize'])
        self.patchStructMem(curTempDataName, int.to_bytes(eSym, byteorder=self.endianess, length=netSize), "e_shentsize")

        shoEntries = self.fillSectionHeader()

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shoff'])
        self.patchStructMem(curTempDataName, int.to_bytes(self.SH_OFFSET, byteorder=self.endianess, length=netSize), "e_shoff")

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shnum'])
        self.patchStructMem(curTempDataName, int.to_bytes(len(self.gSecList), byteorder=self.endianess, length=netSize), "e_shnum")

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shstrndx'])
        self.patchStructMem(curTempDataName, int.to_bytes(len(self.gSecList) - 3, byteorder=self.endianess, length=netSize), "e_shstrndx")

def get_views(bv_t):
    bvs = list(BinaryViewType)
    bv_list = {}
    for bv_i in bvs:
        curtype = bv_i.name
        print(curtype)
        curbv = bv_t.get_view_of_type(curtype)
        if curbv != None:
            bv_list[curtype] = curbv
    return bv_list

def genElfHeader(bv):
    endianess = 'little'
    br = bv.get_view_of_type('Raw')
    bv_t = bv.get_view_of_type('Mapped')
    be = bv.get_view_of_type('ELF')
    if (bv_t == None) or (br == None):
        return
    if (be != None):
        print("already have an Elf file format!")
        return
    if Endianness['LittleEndian'] != bv_t.endianness:
        endianess == 'big'
    
    vmlinux_gen = vmlinux_raw(bv_t, br, endianess, bv_t.address_size, bv_t.arch)
    vmlinux_gen.fillElfHeader()
    print("finished")
