from binaryninja.binaryview import BinaryViewType, BinaryView, Endianness, Architecture
from binaryninja import Symbol, SymbolType, Type, SectionSemantics
import re
from .getStructMemOff import bn_structRetriever
# from .parseSymFile import parseSymFile
from .pyelf import elfSection, elfShndxEnt, elfSymbol, elfSegment
from ..bn_raw_elf_fill.setupTypes import grabLinuxElfTypes

def getEnumName(enumType, enumIndex):
    for i in enumType.members:
        if i.value == enumIndex:
            return i.name
    return None

def getEnumValue(enumType, enumName):
    # if its an empty enumeration, just return 0
    print("{}, {}".format(enumType, enumName))
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

        self.lastlocalsym = 1
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
        # check if the prim we are setting is a bitfield
        bitfieldparse = re.match(r'([a-zA-Z_][a-zA-Z0-9_]*) : ([0-9]+) - ([0-9]+)', args[len(args) - 1])
        if bitfieldparse != None:
            print('found bitfield ({}) is ({})'.format(args[len(args) - 1], bitfieldparse.groups()[0]))
            # args[len(args) - 1] = bitfieldparse.groups()[0]
            newargs = []
            for i in args:
                newargs.append(i)
            newargs[len(newargs) - 1] = bitfieldparse.groups()[0]
            args = newargs
        # get the offset and if its an enum
        targAddr, netOffset, netSize, enumBool = self.bn_sr.getStructMemOff(targetVar, args)
        enumValue = None
        # we have a standard type, just write to it
        if enumBool == None:
            if isinstance(toWrite, int):
                toWrite = int.to_bytes(toWrite, netSize, self.endianess)
            if (len(toWrite) != netSize):
                print("wrong size?!?!? var {}.{} to value {} with len {} and estimate {}".format(targetVar, args, toWrite, len(toWrite), netSize))
                return -1
        # we have an enum, get its val and perform write
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
        # now to read and write the bitfield
        if bitfieldparse != None:
            bf_width = int(bitfieldparse.groups()[2])
            bf_start = int(bitfieldparse.groups()[1])
            bf_mask = ((1 << bf_width) - 1) << bf_start
            toWrite_int = (int.from_bytes(toWrite, self.endianess) & ((1 << bf_width) - 1)) << int(bitfieldparse.groups()[1])
            print('with bitfield mask, new write is {}'.format(hex(toWrite_int)))
            premask = self.br.read(targAddr + netOffset, netSize)
            print("premask read is {}".format(premask))
            postmask = (int.from_bytes(premask, self.endianess) & ~bf_mask) | toWrite_int
            print("postmask read is {}".format(hex(postmask)))
            toWrite = postmask.to_bytes(len(toWrite), self.endianess)
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
        self.patchStructMem(curVarAccessor, curSym.symType, 'st_info', 'st_type_info : 0 - 4')
        self.patchStructMem(curVarAccessor, curSym.symBind, 'st_info', 'st_bind_info : 4 - 8')
        # netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_info'])
        # self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symInfo, byteorder=self.endianess, length=netSize), 'st_info')
        # other
        self.patchStructMem(curVarAccessor, curSym.symOther, 'st_other')
        # netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_other'])
        # self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symOther, byteorder=self.endianess, length=netSize), 'st_other')
        # shndx
        self.patchStructMem(curVarAccessor, curSym.symShndx, 'st_shndx')
        # netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['st_shndx'])
        # self.patchStructMem(curVarAccessor, int.to_bytes(curSym.symShndx, byteorder=self.endianess, length=netSize), 'st_shndx')

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
        # link
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_link'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secLink, byteorder=self.endianess, length=netSize), 'sh_link')
        # info
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_info'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secInfo, byteorder=self.endianess, length=netSize), 'sh_info')
        # align
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_addralign'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secAlign, byteorder=self.endianess, length=netSize), 'sh_addralign')
        # entry_size
        netSize = self.bn_sr.getStructMemOff_netSize(curVarAccessor, ['sh_entsize'])
        self.patchStructMem(curVarAccessor, int.to_bytes(curSec.secEntsz, byteorder=self.endianess, length=netSize), 'sh_entsize')

    # create a section, pad the size and destination if unaligned
    def create_memory_block(self, dest_address, initPadding):
        newSz = self.padInt(initPadding)
        newDest = self.padInt(dest_address)
        print("creating at {}, {} bytes".format(newDest, newSz))
        self.br.insert(newDest, newSz * '\x00')
        self.CUR_TEXT_SZ += newSz

    def get_section_index_by_name(self, name, targ_dict=None):
        index = 0
        if targ_dict == None:
            targ_dict = self.gSecList
        for section_iter in targ_dict:
            section_temp = targ_dict[section_iter]
            if section_temp.name == name:
                return index
            index += 1
        return -1

    def symbol_filter(self, symbol_arg):
        cursym = self.bv.symbols[symbol_arg][0]
        symname = cursym.name
        symtype = cursym.type
        symstuff = re.match(r'(j_)?sub_[0-9a-fA-F]+', symname)
        if symstuff != None:
            return True
        symstuff = re.match(r'__builtin_[\s\S]+', symname)
        if symstuff != None:
            return True
        symstuff = re.match(r'jump_table_[0-9a-fA-F]+', symname)
        if symstuff != None:
            return True
        symstuff = re.match(r'lookup_table_[0-9a-fA-F]+', symname)
        if symstuff != None:
            return True
        return False

    # create the symbol string table
    def createSymStrTab(self):
        Elf_SY_typeS = self.bv.get_type_by_name(self.ElfSym)
        Elf_SY_typeW = Elf_SY_typeS.width

        self.gSymList.append(elfSymbol())
        # determine its associated string table's size
        for each_symbol in self.bv.symbols:
            if self.symbol_filter(each_symbol) == True:
                continue
            print("exporting symname {}".format(each_symbol))
            # get the section owning the target symbol
            cursym = self.bv.symbols[each_symbol][0]
            if cursym.type == SymbolType.ExternalSymbol:
                symsecindex = 'SHT_NULL'
            else:
                foundsecs = self.bv.get_sections_at(cursym.address)
                if foundsecs == []:
                    symsecindex = 'SHT_NULL'
                else:
                    symsecname = foundsecs[0].name
                    symsecindex = self.get_section_index_by_name(symsecname)
                    # bad external symbol has been found, maybe binja generated?
                    if symsecindex == -1:
                        symsecindex = 'SHT_NULL'
                    print("found sections {}".format(foundsecs))
                    print('sections {}'.format(self.bv.sections))
            cursymtype = 'STT_NOTYPE'
            if cursym.type == SymbolType.FunctionSymbol:
                cursymtype = 'STT_FUNC'
            curElfSymbol = elfSymbol(symName=each_symbol, symNameOff=len(self.gStrRaw), symValue=cursym.address, symType=cursymtype, symBind='STB_GLOBAL',
                symOther='STV_DEFAULT', symShndx=symsecindex)
            self.gSymList.append(curElfSymbol)
            self.gStrRaw += each_symbol + '\x00'
            
        # create symbol table at the end of the binary
        symtabbase = self.br.length
        self.create_memory_block(symtabbase, (Elf_SY_typeW * len(self.gSymList)))
        self.gSecList['.symtab'].secSize = (Elf_SY_typeW * len(self.gSymList))

        curTempDataName = '__elf_symbol_table'
        someVarThingSym = Symbol(SymbolType.DataSymbol, symtabbase, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(symtabbase, Type.array(Elf_SY_typeS, len(self.gSymList)))

        symTabIndex = 0
        # print('gsymlist size {}'.format(len(self.gSymList)))
        for curSym in self.gSymList:
            print("cursym {}".format(curSym.symName))
            curVarAccessor = "{}[{}]".format(curTempDataName, symTabIndex)
            self.symEntry(curVarAccessor, curSym, curTempDataName)
            if curSym.symBind == 'STB_LOCAL':
                self.lastlocalsym = symTabIndex + 1
            symTabIndex += 1
            # break
        
        strtabbase = self.br.length
        self.create_memory_block(strtabbase, len(self.gStrRaw))
        self.br.write(strtabbase, self.gStrRaw)
        self.gSecList['.strtab'].secSize = len(self.gStrRaw)
        self.gSecList['.strtab'].secOffset = strtabbase

    def only_extern_sections(self):
        for eachsection in self.bv.sections:
            if self.bv.sections[eachsection].semantics != SectionSemantics.ExternalSectionSemantics:
                False
        return True

    # creates all the sections that will be in the final binary, but does not write them
    # to the final vmlinux
    def allocate_Sections(self):
        symTabName = '.symtab'
        symTabOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += symTabName + '\x00'
        
        strTabName = '.strtab'
        strTabOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += strTabName + '\x00'

        shdrName = '.shstrtab'
        shndxOffTmp = len(self.gShndxRaw)
        self.gShndxRaw += shdrName + '\x00'

        self.gSecList['null_prefix'] = elfSection()

        print('{} and {}: {} == {}'.format(self.only_extern_sections(), self.bv.segments[0] == self.bv.start, self.bv.segments[0], self.bv.start))
        if self.only_extern_sections() == True:
            equivalentseg = self.bv.segments[0]
            if equivalentseg.start == self.bv.start:
                newtextname = '.text'
                self.bv.add_auto_section('.text', equivalentseg.start, equivalentseg.length, SectionSemantics.ReadOnlyCodeSectionSemantics, 'PROGBITS', 0x40)
                newtext = elfSection(newtextname, len(self.gShndxRaw), 'SHT_{}'.format('PROGBITS'), secFlags='SHF_ALLOC | SHF_EXECINSTR',
                    secAddr=equivalentseg.start, secOffset=equivalentseg.data_offset, secSize=equivalentseg.length, secLink=0,
                    secInfo=0, secAlign=0x40, secEntsz=0)
                print('created new text section')
                self.gShndxRaw += newtextname + '\x00'
                self.gSecList[newtextname] = newtext

        # first we want to append the valid sections that our binary has
        for cursecname in self.bv.sections:
            bvsec = self.bv.sections[cursecname]
            
            # for sections doesn't have a raw, gonna continue
            if cursecname not in self.br.sections.keys():
                continue
            brsec = self.br.sections[cursecname]
            curShndx_off = len(self.gShndxRaw)
            self.gShndxRaw += cursecname + '\x00'
            sh_flags = 0
            if bvsec.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics:
                sh_flags = 'SHF_ALLOC | SHF_EXECINSTR'
            elif bvsec.semantics == SectionSemantics.ReadWriteDataSectionSemantics:
                sh_flags = 'SHF_ALLOC | SHF_WRITE'
            elif bvsec.semantics == SectionSemantics.ReadOnlyDataSectionSemantics:
                sh_flags = 'SHF_ALLOC'
            self.gSecList[cursecname] = elfSection(cursecname, secNameOff=curShndx_off, secType='SHT_{}'.format(bvsec.type),
                secFlags=sh_flags, secAddr=bvsec.start, secOffset=brsec.start, secSize=bvsec.length, secAlign=bvsec.align)

        # now create the symbol table section, this will need to be corrected when
        # the symbol table has been finished, but since len is 0 the below math will
        # eval to 0
        FIXME_SYMTABSZ = self.bv.get_type_by_name(self.ElfSym).width * (len(self.gSymList))
        FIXME_SYMTABINFO = 1
        FIXME_SYMTABLINK = 0
        symSec = elfSection(name=symTabName, secNameOff=symTabOffTmp, secType='SHT_SYMTAB', secFlags=0,
            secAddr=0, secOffset=self.br.length, secSize=FIXME_SYMTABSZ, secLink=FIXME_SYMTABLINK,
            secInfo=FIXME_SYMTABINFO, secAlign=0x4, secEntsz=self.bv.get_type_by_name(self.ElfSym).width)

        # create the strtab, likewise since the strtab hasn't been initialized yet this will initiate to 0
        FIXME_STRTABSZ = len(self.gStrRaw)
        FIXME_STRTAB = self.br.length
        strSec = elfSection(name=strTabName, secNameOff=strTabOffTmp, secType='SHT_STRTAB', secFlags=0,
            secAddr=0, secOffset=FIXME_STRTAB, secSize=FIXME_STRTABSZ, secLink=0, secInfo=0, secAlign=0x1,
            secEntsz=0)

        # create the shstrtab section for the section headers
        FIXME_SHSTRTAB = self.CUR_TEXT_SZ
        shstrSec = elfSection(name=shdrName, secNameOff=shndxOffTmp, secType='SHT_STRTAB', secFlags=0, 
            secAddr=0, secOffset=FIXME_SHSTRTAB, secSize=len(self.gShndxRaw), secLink=0, secInfo=0, secAlign=0x1,
            secEntsz=0)

        self.gSecList[symTabName] = symSec
        self.gSecList[strTabName] = strSec
        self.gSecList[shdrName] = shstrSec

        self.gSecList[symTabName].secLink = self.get_section_index_by_name(strTabName)

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
        someVarThingSym = Symbol(SymbolType.DataSymbol, secheadbase, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(secheadbase, Type.array(Elf_SH_typeS, len(self.bv.sections)))

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
            return -1

        curTempDataName = '__elf_header'
        curHeadAddress = 0
        someVarThingSym = Symbol(SymbolType.DataSymbol, curHeadAddress, curTempDataName)
        self.br.define_user_symbol(someVarThingSym)
        self.br.define_user_data_var(curHeadAddress, Elf_Head_typeS)
        self.patchStructMem(curTempDataName, b"\x7fELF", "e_ident", "signature")
        
        # 32 or 64 bit byte, 1 or 2
        e_class_local = None
        if self.bv.address_size == 4:
            e_class_local = 1
        elif self.bv.address_size == 8:
            e_class_local = 2
        e_class_localb = e_class_local.to_bytes(1, self.endianess)
        self.patchStructMem(curTempDataName, e_class_localb, "e_ident", "file_class")
        
        # little or big, 1 or 2
        e_encode = None
        if self.endianess == 'little':
            e_encode = 1
        elif self.endianess == 'big':
            e_encode = 2
        e_encodeb = e_encode.to_bytes(1, self.endianess)
        self.patchStructMem(curTempDataName, e_encodeb, "e_ident", "encoding")

        self.patchStructMem(curTempDataName, b"\x01", "e_ident", "version")
        self.patchStructMem(curTempDataName, b"\x61", "e_ident", "os")
        self.patchStructMem(curTempDataName, b"\x00", "e_ident", "abi_version")

        # default ET_EXEC for executable file
        e_type_l = "ET_EXEC"
        self.patchStructMem(curTempDataName, e_type_l, "e_type")
        
        # get architecture flag
        e_arch_l = None
        if self.bv.arch == Architecture['armv7']:
            e_arch_l = 'EM_ARM'
        
        self.patchStructMem(curTempDataName, e_arch_l, "e_machine")

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
        if self.createSymStrTab() == -1:
            return -1
        self.createShndx()

        shoEntries = self.fillSectionHeader()

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shoff'])
        self.patchStructMem(curTempDataName, int.to_bytes(self.SH_OFFSET, byteorder=self.endianess, length=netSize), "e_shoff")

        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shnum'])
        self.patchStructMem(curTempDataName, int.to_bytes(len(self.gSecList), byteorder=self.endianess, length=netSize), "e_shnum")

        shstrtabindx = self.get_section_index_by_name(".shstrtab")
        netSize = self.bn_sr.getStructMemOff_netSize(curTempDataName, ['e_shstrndx'])
        self.patchStructMem(curTempDataName, int.to_bytes(shstrtabindx, byteorder=self.endianess, length=netSize), "e_shstrndx")

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
