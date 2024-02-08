from binaryninja.binaryview import BinaryViewType, BinaryView, Endianness
from binaryninja import Symbol, SymbolType, Type
import re
from .getStructMemOff import bn_structRetriever
# from .parseSymFile import parseSymFile
from .pyelf import elfSection, elfShndxEnt, elfSymbol, elfSegment
from .bn_raw_elf_fill.setupTypes import grabLinuxElfTypes

def getEnumName(enumType, enumIndex):
    for i in enumType.members:
        if i.value == enumIndex:
            return i.name
    return None

def getEnumValue(enumType, enumName):
    # if its an empty enumeration, just return 0
    if enumName == '':
        return 0
    for i in enumType.members:
        if i.name == enumName:
            return i.value
    return None

def fetchStructMem(targetVar, *args):
    targAddr, netOffset, netSize, enumBool = self.bn_sr.getStructMemOff(targetVar, args)
    retValue = br.read(targAddr + netOffset, netSize)
    return retValue

def strings_to_enumarr(enumslist):
    enumout = ''
    for enumeach in enumslist:
        if enumeach != '':
            if enumout == '':
                enumout = enumeach
            else:
                enumout = enumout + ' | ' + enumeach
    return enumout

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
            self.TEXT_OFFSET = (int((len(self.bv.segments) * prgmsz + elfsz) / 0x1000) * 0x1000) + 0x1000
        
        self.gSymList = []
        self.gSecList = {}
        self.gPhdrList = []
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
                print("wrong size?!?!? var {}.{} to value {} with len {} and estimate {}".format(targetVar, args, toWrite, len(toWrite), netSize))
                return -1
        if enumBool != None:
            if isinstance(toWrite, str):
                print("current enum to annotate ({})".format(toWrite))
                annotateEnum = toWrite.split(' | ')
                enumValue = 0
                for i in annotateEnum:
                    enumValue = enumValue | getEnumValue(enumBool, i)
            else:
                enumValue = toWrite
            toWrite = int.to_bytes(enumValue, byteorder=self.endianess, length=netSize)
        print('writing to {}:{}.{} {}'.format(hex(targAddr + netOffset), targetVar, args, toWrite))
        retValue = self.br.write(targAddr + netOffset, toWrite)
        return retValue

    def phEntry(self, curVarAccessor, phEntry):
        print("p_type {}".format(phEntry.p_type))
        self.patchStructMem(curVarAccessor, phEntry.p_type, 'p_type')
        
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['p_offset'])
        self.patchStructMem(curVarAccessor, int.to_bytes(phEntry.p_offset, byteorder=self.endianess, length=netSize), 'p_offset')

        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['p_vaddr'])
        self.patchStructMem(curVarAccessor, int.to_bytes(phEntry.p_vaddr, byteorder=self.endianess, length=netSize), 'p_vaddr')
        
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['p_paddr'])
        self.patchStructMem(curVarAccessor, int.to_bytes(phEntry.p_paddr, byteorder=self.endianess, length=netSize), 'p_paddr')

        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['p_filesz'])
        self.patchStructMem(curVarAccessor, int.to_bytes(phEntry.p_filesz, byteorder=self.endianess, length=netSize), 'p_filesz')

        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['p_memsz'])
        self.patchStructMem(curVarAccessor, int.to_bytes(phEntry.p_memsz, byteorder=self.endianess, length=netSize), 'p_memsz')

        print("p_flags {}".format(phEntry.p_flags))
        self.patchStructMem(curVarAccessor, phEntry.p_flags, 'p_flags')

        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['p_align'])
        self.patchStructMem(curVarAccessor, int.to_bytes(phEntry.p_align, byteorder=self.endianess, length=netSize), 'p_align')

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
            self.patchStructMem(curVarAccessor, int.to_bytes(self.bv.get_type_by_name(self.ElfSym).width, byteorder=self.endianess, length=netSize), 'sh_entsize')

    # create a section, pad the size and destination if unaligned
    def create_memory_block(self, dest_address, initPadding):
        newSz = self.padInt(initPadding)
        newDest = self.padInt(dest_address)
        print("creating at {}, {} bytes".format(newDest, newSz))
        self.br.insert(newDest, newSz * '\x00')
        self.CUR_TEXT_SZ += newSz

    def get_section_index_by_name(self, name):
        index = 0
        for section_iter in self.bv.gSecList:
            section_temp = self.bv.gSecList[section_iter]
            if section_temp.name == name:
                return index
        return -1

    def symbol_filter(self, symbol_arg):
        symname = self.bv.symbols[symbol_arg][0].name
        symstuff = re.match(r'(j_)?sub_[.]+', symname)
        if symstuff != None:
            return False
        return True

    # create the symbol string table
    def createSymStrTab(self):
        Elf_SY_typeS = self.bv.get_type_by_name(self.ElfSym)
        Elf_SY_typeW = Elf_SY_typeS.width
        symtabbase = self.br.length

        # determine its associated string table's size
        for each_symbol in self.bv.symbols:
            if self.symbol_filter(each_symbol) == True:
                continue
            print("exporting symname {}".format(each_symbol))
            # get the section owning the target symbol
            cursym = self.bv.symbols[each_symbol][0]
            symsecname = self.bv.get_sections_at(cursym.address)[0].name
            symsecindex = self.get_section_index_by_name(symsecname)
            curElfSymbol = elfSymbol(symName=each_symbol, symNameOff=len(self.gStrRaw), symValue=self.bv.symbols[each_symbol].address, symInfo=0,
                symShndx=symsecindex)
            self.gSymList.append(curElfSymbol)
            self.gStrRaw += each_symbol + '\x00'
            
        # create symbol table at the end of the binary
        self.create_memory_block(symtabbase, (Elf_SY_typeW * len(self.gSymList)))
        self.gSecList['.symtab'].secSize = (Elf_SY_typeW * len(self.gSymList))

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
        
        strtabbase = self.br.length
        self.create_memory_block(strtabbase, len(self.gStrRaw))
        self.br.write(strtabbase, self.gStrRaw)
        self.gSecList['.strtab'].secSize = len(self.gStrRaw)
        self.gSecList['.strtab'].secOffset = strtabbase

    # creates all the sections that will be in the final binary, but does not write them
    # to the final vmlinux
    def allocate_Sections(self):
        shdrName = '.shstrtab'
        shndxOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += shdrName + '\x00'
        
        symTabName = '.symtab'
        symTabOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += symTabName + '\x00'

        strTabName = '.strtab'
        strTabOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += strTabName + '\x00'

        # first we want to append the valid sections that our binary has
        for cursecname in self.bv.sections:
            bvsec = self.bv.sections[cursecname]
            
            # for sections doesn't have a raw, gonna continue
            if cursecname not in self.br.sections.keys():
                continue
            brsec = self.br.sections[cursecname]
            curShndx_off = len(self.gShndxRaw)
            self.gShndxRaw += cursecname + '\x00'
            self.gSecList[cursecname] = elfSection(cursecname, curShndx_off, 'SHT_{}'.format(bvsec.type), bvsec.semantics, bvsec.start, brsec.start, bvsec.length, bvsec.align)

        # create the shstrtab section for the section headers
        shstrSec = elfSection(shdrName, shndxOffTmp, 'SHT_STRTAB', 0, 0, self.CUR_TEXT_SZ, len(self.gShndxRaw), 0x1)

        # now create the symbol table section, this will need to be corrected when
        # the symbol table has been finished, but since len is 0 the below math will
        # eval to 0
        FIXME_SYMTABSZ = self.bv.get_type_by_name(self.ElfSym).width * (len(self.gSymList))
        symSec = elfSection(symTabName, symTabOffTmp, 'SHT_SYMTAB', 0, 0, self.br.length, FIXME_SYMTABSZ, 0x4)

        # create the strtab, likewise since the strtab hasn't been initialized yet this will initiate to 0
        FIXME_STRTABSZ = len(self.gStrRaw)
        FIXME_STRTAB = self.br.length
        strSec = elfSection(strTabName, strTabOffTmp, 'SHT_STRTAB', 0, 0, FIXME_STRTAB, FIXME_STRTABSZ, 0x1)

        self.gSecList[shdrName] = shstrSec
        self.gSecList[symTabName] = symSec
        self.gSecList[strTabName] = strSec


    # create a section string table and write it to the vmlinux
    def createShndx(self):

        # then create the .shstrtab, which will have size equal to the determined
        # gShndRaw
        shstrbase = self.br.length
        self.create_memory_block(shstrbase, len(self.gShndxRaw))
        self.br.write(shstrbase, self.gShndxRaw)
        self.gSecList['.shstrtab'].secOffset = shstrbase        

    def fillProgramHeader(self, pho):
        Elf_PH_typeS = self.bv.get_type_by_name(self.ElfPrgm)

        curTempDataName = "__elf_program_headers"
        someVarThingSym = Symbol(SymbolType.DataSymbol, pho, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(pho, Type.array(Elf_PH_typeS, 1))

        entryIndex = 0
        if len(self.bv.segments) == 0:
            curphdr = elfSegment(p_type="PT_LOAD", p_offset=self.TEXT_OFFSET, p_vaddr=self.TEXT_ENTRY, p_paddr=0, p_filesz=self.OG_TEXT_SZ, p_memsz=self.OG_TEXT_SZ, p_flags="PF_X | PF_W | PF_R", p_align=0x10000)
            self.gPhdrList.append(curphdr)

        # this has an entry pointing to the beginning of the section header, so
        for phEntry in self.bv.segments:
            ph_flags = strings_to_enumarr([int(phEntry.readable) * 'PF_R', int(phEntry.writable) * 'PF_W', int(phEntry.executable) * 'PF_X'])
            curphdr = elfSegment(p_type='PT_LOAD', p_offset=phEntry.data_offset + self.TEXT_OFFSET, p_vaddr=phEntry.start, p_paddr=0, p_filesz=phEntry.data_length, p_memsz=phEntry.length, p_flags=ph_flags, p_align=0)
            print(curphdr.p_type, curphdr.p_offset, hex(curphdr.p_vaddr), curphdr.p_paddr, hex(curphdr.p_filesz), hex(curphdr.p_memsz), curphdr.p_flags, curphdr.p_align)
            self.gPhdrList.append(curphdr)

        for curphdr in self.gPhdrList:
            self.phEntry('{}[{}]'.format(curTempDataName, entryIndex), curphdr)
            entryIndex += 1

        return entryIndex
    
    # it should be .shstrtab
    # section header
    # symtab
    # strtab
    def fillSectionHeader(self):
        # totalSections = len(self.gSecList)
        Elf_SH_typeS = self.bv.get_type_by_name(self.secHeadName)

        secheadsz = Elf_SH_typeS.width * len(self.gSecList)
        secheadbase = self.br.length
        self.create_memory_block(secheadbase, secheadsz)
        # if anywhere to use the section header offset, it is right here.
        self.SH_OFFSET = secheadbase

        newSz = self.padInt(self.CUR_TEXT_SZ)
        self.CUR_TEXT_SZ = newSz
        
        curTempDataName = '__elf_section_headers'
        someVarThingSym = Symbol(SymbolType.DataSymbol, self.CUR_TEXT_SZ, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(self.CUR_TEXT_SZ, Type.array(Elf_SH_typeS, len(self.bv.sections)))

        secHeadIndex = 0
        for curSec in self.gSecList:
            curSectmp = self.gSecList[curSec]
            curVarAccessor = "{}[{}]".format(curTempDataName, secHeadIndex)
            self.shEntry(curVarAccessor, curSectmp, self.secHeadName)
            secHeadIndex += 1

    def fillElfHeader(self, symFile=None):
        # print(hex(CUR_TEXT_SZ))
        grabLinuxElfTypes(self.bv)
        self.create_memory_block(0, self.TEXT_OFFSET)
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

        self.allocate_Sections()
        self.createSymStrTab()
        self.createShndx()

        # shoEntries = self.fillSectionHeader()

        # netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shoff'])
        # self.patchStructMem(curTempDataName, int.to_bytes(self.SH_OFFSET, byteorder=self.endianess, length=netSize), "e_shoff")

        # netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shnum'])
        # self.patchStructMem(curTempDataName, int.to_bytes(len(self.gSecList), byteorder=self.endianess, length=netSize), "e_shnum")

        # netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shstrndx'])
        # self.patchStructMem(curTempDataName, int.to_bytes(len(self.gSecList) - 3, byteorder=self.endianess, length=netSize), "e_shstrndx")

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
