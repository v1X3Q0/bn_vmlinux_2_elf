import re

br = bv.get_view_of_type('Raw')
TEXT_OFFSET = 0x18000
OG_TEXT_SZ = len(br)
SH_OFFSET = 0
CUR_TEXT_SZ = OG_TEXT_SZ

TEXT_ENTRY = 0xc0008000
TEXT_END = 0

SYM_SECTLIST = {
    "_stext": ".init",
    "_text": ".text",
    "__start_rodata": "__ksymtab",
    "__start___ksymtab_gpl": "__ksymtab_gpl",
    "__start___kcrctab": "__ksymtab_strings",
    "__start___param": "__param",
    "_etext": ".data"
}

INIT_SYM = '_stext'
TEXT_SYM = '_text'
KSYMTAB_SYM = '__start_rodata'
KSYMTAB_GPL_SYM = '__start___ksymtab_gpl'
KSYMTAB_STRINGS_SYM = '__start___kcrctab'
PARAM_SYM = '__start___param'

gSymList = []
gSecList = []
gShndxRaw = '\x00'
gStrRaw = '\x00'

def getIndexObject(targetVar):
    potentialIndex = re.search(r"[\[\d\]]+", targetVar)
    targVarReal = targetVar
    if potentialIndex != None:
        potentialIndex = potentialIndex[0]
        targVarReal = targetVar.replace(potentialIndex, '')
        potentialIndex = potentialIndex.replace(']', '').replace('[', '')
        potentialIndex = int(potentialIndex)

    return targVarReal, potentialIndex

def getRealStructType(structDesig):
    resStruct = None
    namedStruct = structDesig.get_string_before_name()
    if 'struct ' in namedStruct:
        resStruct = br.get_type_by_name(namedStruct.replace("struct ", ''))
    return resStruct

def getRealEnumType(enumDesig):
    resEnum = None
    namedEnum = enumDesig.get_string_before_name()
    if 'enum ' in namedEnum:
        resEnum = br.get_type_by_name(namedEnum.replace("enum ", ''))
    return resEnum

# potential ways to call
# "__elf_program_headers[2]", "type"
def getStructMemOff(targetVar, args):
    netOffset = 0
    netSize = 0
    targetVar, potentialIndex = getIndexObject(targetVar)
    targVarSym = br.get_symbol_by_raw_name(targetVar)
    targVarVar = br.get_data_var_at(targVarSym.address)
    if potentialIndex != None:
        nextTargVar = targVarVar.type.get_string_before_name()
        if 'struct ' in nextTargVar:
            nextTargVar = br.get_type_by_name(nextTargVar.replace("struct ", '')).structure
        else:
            nextTargVar = targVarVar.type.element_type
        netOffset += (nextTargVar.width * potentialIndex)
        # targVarVar.type.get_string_before_name()
    else:
        nextTargVar = targVarVar.type.structure
    enumBool = None
    if nextTargVar != None:
        # iterate struct members
        for i in args:
            curTargVar = nextTargVar
            curTargVarName, potentialIndex = getIndexObject(i)
            # for each member in the current struct being observed
            for eachMem in curTargVar.members:
                # if the struct member's name is the target arg
                if eachMem.name == curTargVarName:
                    if potentialIndex != None:
                        nextTargVar = targVarVar.type.get_string_before_name()
                        if 'struct ' in nextTargVar:
                            nextTargVar = br.get_type_by_name(nextTargVar.replace("struct ", ''))
                        else:
                            nextTargVar = targVarVar.type.element_type
                        netOffset += (nextTargVar.width * potentialIndex)
                    netOffset += eachMem.offset
                    netSize = eachMem.type.width
                    potStructType = getRealStructType(eachMem.type)
                    potEnumType = getRealEnumType(eachMem.type)
                    if potStructType != None:
                        nextTargVar = potStructType.structure
                    elif eachMem.type.element_type != None:
                        nextTargVar = eachMem.type.element_type
                    elif potEnumType != None:
                        enumBool = potEnumType.enumeration
                    break
    else:
        netSize = targVarVar.type.width
    # we have broken out, optimistically we are at the most primitive type
    # print("final width ", netSize)
    return targVarSym.address, netOffset, netSize, enumBool

def getStructMemOff_targAddr(targetVar, args):
    targAddr, _, _, _ = getStructMemOff(targetVar, args)
    return targAddr

def getStructMemOff_netOffset(targetVar, args):
    _, netOffset, _, _ = getStructMemOff(targetVar, args)
    return netOffset

def getStructMemOff_netSize(targetVar, args):
    _, _, netSize, _ = getStructMemOff(targetVar, args)
    return netSize

def getStructMemOff_enumBool(targetVar, args):
    _, _, _, enumBool = getStructMemOff(targetVar, args)
    return enumBool

def getEnumName(enumType, enumIndex):
    for i in enumType.members:
        if i.value == enumIndex:
            return i.name
    return None

def getEnumValue(enumType, enumName):
    for i in enumType.members:
        if i.name == enumName:
            return i.value
    return None

def patchStructMem(targetVar, toWrite, *args):
    targAddr, netOffset, netSize, enumBool = getStructMemOff(targetVar, args)
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
        toWrite = int.to_bytes(enumValue, byteorder='little', length=netSize)
    retValue = br.write(targAddr + netOffset, toWrite)
    return retValue

def fetchStructMem(targetVar, *args):
    targAddr, netOffset, netSize, enumBool = getStructMemOff(targetVar, args)
    retValue = br.read(targAddr + netOffset, netSize)
    return retValue

class elfSymbol:
    def __init__(self, symName=0, symNameOff=0, symValue=0, symInfo=0, symOther=0, symShndx=0):
        self.symName = symName
        self.symNameOff = symNameOff
        self.symValue = symValue
        self.symInfo = symInfo
        self.symOther = symOther
        self.symShndx = symShndx

class elfShndxEnt:
    def __init__(self, name, address, size):
        self.name = name
        self.address = address
        self.size = size

class elfSection:
    def __init__(self, secName=0, secNameOff=0, secType=0, secFlags=0, secAddr=0, secOffset=0, secSize=0, secAlign=0):
        self.secName = secName
        self.secNameOff = secNameOff
        self.secType = secType
        self.secFlags = secFlags
        self.secAddr = secAddr
        self.secOffset = secOffset
        self.secSize = secSize
        self.secAlign = secAlign

def createHeaderSection(initPadding):
    global CUR_TEXT_SZ
    br.insert(0, initPadding * '\x00')
    CUR_TEXT_SZ += initPadding

def phEntry(phOff, p_type, offset, virtual_address, physical_address, file_size, memory_size, flags, align):
    patchStructMem(phOff, p_type, 'type')
    
    netSize = getStructMemOff_netSize(phOff, ['offset'])
    patchStructMem(phOff, int.to_bytes(offset, byteorder='little', length=netSize), 'offset')

    netSize = getStructMemOff_netSize(phOff, ['virtual_address'])
    patchStructMem(phOff, int.to_bytes(virtual_address, byteorder='little', length=netSize), 'virtual_address')
    
    netSize = getStructMemOff_netSize(phOff, ['physical_address'])
    patchStructMem(phOff, int.to_bytes(physical_address, byteorder='little', length=netSize), 'physical_address')

    netSize = getStructMemOff_netSize(phOff, ['file_size'])
    patchStructMem(phOff, int.to_bytes(file_size, byteorder='little', length=netSize), 'file_size')

    netSize = getStructMemOff_netSize(phOff, ['memory_size'])
    patchStructMem(phOff, int.to_bytes(memory_size, byteorder='little', length=netSize), 'memory_size')

    patchStructMem(phOff, flags, 'flags')

    netSize = getStructMemOff_netSize(phOff, ['align'])
    patchStructMem(phOff, int.to_bytes(align, byteorder='little', length=netSize), 'align')

def fillProgramHeader(pho):
    Elf32_PH_typeS = br.get_type_by_name("Elf32_ProgramHeader")
    curTempDataName = "__elf_program_headers"
    someVarThingSym = Symbol(SymbolType.DataSymbol, pho, curTempDataName)
    br.define_user_symbol(someVarThingSym)
    br.define_user_data_var(pho, Type.array(Elf32_PH_typeS, 1))
    entryIndex = 0
    # this has an entry pointing to the beginning of the section header, so
    phEntry('{}[{}]'.format(curTempDataName, entryIndex), "PT_LOAD", TEXT_OFFSET,
        TEXT_ENTRY, TEXT_ENTRY, OG_TEXT_SZ, OG_TEXT_SZ, "PF_X | PF_W | PF_R",
        0x10000)
    entryIndex += 1
    return entryIndex

def parseSymFile(symFile, symStart='stext', symEnd='_etext'):
    global TEXT_ENTRY
    global TEXT_END
    global OG_TEXT_SZ
    global CUR_TEXT_SZ
    global gSymList
    global gShndxRaw
    global gStrRaw
    f = open(symFile, "r")
    g = f.readlines()
    f.close()
    secPrev = 0
    gSymList.append(elfSymbol())
    gSecList.append(elfSection())
    szTotal = 0
    for i in g:
        # populate section
        i = i.replace('\n', '')
        lineDexed = i.split(' ')
        # symCurType = parseSymType(lineDexed[1])
        symCurAddr = int(lineDexed[0], 0x10)
        symCurName = lineDexed[2]
        symCurNameOff = len(gStrRaw)
        gStrRaw += symCurName + '\x00'
        if symCurName == symStart:
            TEXT_ENTRY = symCurAddr
        elif symCurName == symEnd:
            TEXT_END = symCurAddr
        
        if symCurName in SYM_SECTLIST.keys():
            curSectName = SYM_SECTLIST[symCurName]
            shndxLen = len(gShndxRaw)
            curShndxStr = curSectName + '\x00'
            gShndxRaw += curShndxStr

            offReal = (symCurAddr - TEXT_ENTRY) + TEXT_OFFSET
            secSize = offReal - secPrev
            # print("new {}, old {} sz {}".format(hex(offReal), hex(secPrev), hex(secSize)))
            if curSectName == '.init':
                curSectFlags = 'SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR'
                curAlign = 0x20
            elif curSectName == '.text':
                curSectFlags = 'SHF_ALLOC | SHF_EXECINSTR'
                curAlign = 0x400
            elif curSectName == '__ksymtab':
                curSectFlags = 'SHF_ALLOC'
                curAlign = 0x4
            elif curSectName == '__ksymtab_gpl':
                curSectFlags = 'SHF_ALLOC'
                curAlign = 0x4
            elif curSectName == '__ksymtab_strings':
                curSectFlags = 'SHF_ALLOC'
                curAlign = 0x1
            elif curSectName == '__param':
                curSectFlags = 'SHF_ALLOC'
                curAlign = 0x4
            elif curSectName == '.data':
                curSectFlags = 'SHF_WRITE | SHF_ALLOC'
                curAlign = 0x20

            curSecTmp = elfSection(curSectName, shndxLen, 'SHT_PROGBITS', curSectFlags, symCurAddr, offReal, 0, curAlign)
            curElfSymbol = elfSymbol(symName=curSectName, symValue=symCurAddr, symInfo=0x03, symShndx=(len(gSecList) + 1))
            gSymList.insert(len(gSecList), curElfSymbol)
            if len(gSecList) > 1:
                gSecList[len(gSecList) - 1].secSize = secSize
                # print("{} off {} curSz {}".format(gSecList[len(gSecList) - 1].secName, hex(gSecList[len(gSecList) - 1].secOffset),
                #     hex(secSize)))
                szTotal += secSize

            gSecList.append(curSecTmp)

            secPrev = offReal

        curElfSymbol = elfSymbol(symName=symCurName, symNameOff=symCurNameOff, symValue=symCurAddr, symInfo=0,
            symShndx=(len(gSecList)))
        gSymList.append(curElfSymbol)

        if symCurName == symEnd:
            break

        # if curElfSymbol.symName in SYM_SECTLIST.keys():
        # at this point, CUR_TEXT_SZ is the file whole size, rawSz+0x18000
        # secOffPrev = 
    secSize = gSecList[len(gSecList) - 2].secOffset + gSecList[len(gSecList) - 2].secSize
    # print(hex(secSize))
    secSize = CUR_TEXT_SZ - secSize
    # print(hex(secSize))
    gSecList[len(gSecList) - 1].secSize = secSize
    szTotal += secSize
    # print("curTextSz {} {} at secof {}, szTotal {}".format(hex(CUR_TEXT_SZ), gSecList[len(gSecList) - 1].secName,
    #     hex(gSecList[len(gSecList) - 1].secOffset), hex(szTotal)))
    return gSymList

def syEntry(curVarAccessor, curSym, curTempDataName):
    # name
    netSize = getStructMemOff_netSize(curVarAccessor, ['name'])
    patchStructMem(curVarAccessor, int.to_bytes(curSym.symNameOff, byteorder='little', length=netSize), 'name')
    # value
    netSize = getStructMemOff_netSize(curVarAccessor, ['value'])
    patchStructMem(curVarAccessor, int.to_bytes(curSym.symValue, byteorder='little', length=netSize), 'value')
    # size
    netSize = getStructMemOff_netSize(curVarAccessor, ['size'])
    patchStructMem(curVarAccessor, int.to_bytes(0, byteorder='little', length=netSize), 'size')
    # info
    netSize = getStructMemOff_netSize(curVarAccessor, ['info'])
    patchStructMem(curVarAccessor, int.to_bytes(curSym.symInfo, byteorder='little', length=netSize), 'info')
    # other
    netSize = getStructMemOff_netSize(curVarAccessor, ['other'])
    patchStructMem(curVarAccessor, int.to_bytes(curSym.symOther, byteorder='little', length=netSize), 'other')
    # shndx
    netSize = getStructMemOff_netSize(curVarAccessor, ['shndx'])
    patchStructMem(curVarAccessor, int.to_bytes(curSym.symShndx, byteorder='little', length=netSize), 'shndx')

# create the 
def createSymStrTab():
    global CUR_TEXT_SZ
    global gStrRaw
    curTempDataName = "Elf32_Sym"

    Elf32_SY_typeS = br.get_type_by_name(curTempDataName)
    Elf32_SY_typeW = Elf32_SY_typeS.width
    br.insert(CUR_TEXT_SZ, (Elf32_SY_typeW * len(gSymList)) * "\x00")
    
    curTempDataName = '__elf_symbol_table'
    someVarThingSym = Symbol(SymbolType.DataSymbol, CUR_TEXT_SZ, curTempDataName)
    br.define_user_symbol(someVarThingSym)
    br.define_user_data_var(CUR_TEXT_SZ, Type.array(Elf32_SY_typeS, len(gSymList)))

    CUR_TEXT_SZ += (Elf32_SY_typeW * len(gSymList))

    symTabIndex = 0

    for curSym in gSymList:
        curVarAccessor = "{}[{}]".format(curTempDataName, symTabIndex)
        syEntry(curVarAccessor, curSym, curTempDataName)
        symTabIndex += 1
        # break
    
    br.insert(CUR_TEXT_SZ, gStrRaw)

def padInt(targInt, padSz=4):
    if (targInt % 4) != 0:
        paddSec = (4 - (targInt % 4))
        targInt = targInt + paddSec
    return targInt

def createShndx():
    global gShndxRaw
    global gSecList
    global CUR_TEXT_SZ
    global gStrRaw

    shdrName = '.shstrtab'
    shndxOffTmp = len(gShndxRaw)
    gShndxRaw += shdrName + '\x00'
    
    symTabName = '.symtab'
    symTabOffTmp = len(gShndxRaw)
    gShndxRaw += symTabName + '\x00'

    strTabName = '.strtab'
    strTabOffTmp = len(gShndxRaw)
    gShndxRaw += strTabName + '\x00'
    shstrSec = elfSection(shdrName, shndxOffTmp, 'SHT_STRTAB', 0, 0, CUR_TEXT_SZ, len(gShndxRaw), 0x1)

    textPostStr = CUR_TEXT_SZ + len(gShndxRaw)
    textPostStr = padInt(textPostStr, 4)

    textPostStr = textPostStr + (br.get_type_by_name("Elf32_SectionHeader").width * (len(gSecList) + 3))
    symTabSz = br.get_type_by_name("Elf32_Sym").width * (len(gSymList))

    symSec = elfSection(symTabName, symTabOffTmp, 'SHT_SYMTAB', 0, 0, textPostStr, symTabSz, 0x4)

    testPostSec = textPostStr + symTabSz
    
    strSec = elfSection(shdrName, strTabOffTmp, 'SHT_STRTAB', 0, 0, testPostSec, len(gStrRaw), 0x1)

    gSecList.append(shstrSec)
    gSecList.append(symSec)
    gSecList.append(strSec)

    br.insert(CUR_TEXT_SZ, gShndxRaw)
    CUR_TEXT_SZ += len(gShndxRaw)


def shEntry(curVarAccessor, curSec, secHeadName):
    # name
    netSize = getStructMemOff_netSize(curVarAccessor, ['name'])
    patchStructMem(curVarAccessor, int.to_bytes(curSec.secNameOff, byteorder='little', length=netSize), 'name')
    # type
    netSize = getStructMemOff_netSize(curVarAccessor, ['type'])
    patchStructMem(curVarAccessor, curSec.secType, 'type')
    # flags
    netSize = getStructMemOff_netSize(curVarAccessor, ['flags'])
    patchStructMem(curVarAccessor, curSec.secFlags, 'flags')
    # address
    netSize = getStructMemOff_netSize(curVarAccessor, ['address'])
    patchStructMem(curVarAccessor, int.to_bytes(curSec.secAddr, byteorder='little', length=netSize), 'address')
    # offset
    netSize = getStructMemOff_netSize(curVarAccessor, ['offset'])
    patchStructMem(curVarAccessor, int.to_bytes(curSec.secOffset, byteorder='little', length=netSize), 'offset')        
    # size
    # print("section {} size {}".format(curSec.secName, hex(curSec.secSize)))
    netSize = getStructMemOff_netSize(curVarAccessor, ['size'])
    patchStructMem(curVarAccessor, int.to_bytes(curSec.secSize, byteorder='little', length=netSize), 'size')
    # align
    netSize = getStructMemOff_netSize(curVarAccessor, ['align'])
    patchStructMem(curVarAccessor, int.to_bytes(curSec.secAlign, byteorder='little', length=netSize), 'align')
    if curSec.secName == '.symtab':
        # link
        netSize = getStructMemOff_netSize(curVarAccessor, ['link'])
        patchStructMem(curVarAccessor, int.to_bytes(len(gSecList) - 1, byteorder='little', length=netSize), 'link')
        # info
        netSize = getStructMemOff_netSize(curVarAccessor, ['info'])
        patchStructMem(curVarAccessor, int.to_bytes(0x807a, byteorder='little', length=netSize), 'info')
        # entry_size
        netSize = getStructMemOff_netSize(curVarAccessor, ['entry_size'])
        patchStructMem(curVarAccessor, int.to_bytes(br.get_type_by_name("Elf32_Sym").width, byteorder='little', length=netSize), 'entry_size')


# it should be .shstrtab
# section header
# symtab
# strtab
def fillSectionHeader():
    global gSecList
    global CUR_TEXT_SZ
    global SH_OFFSET
    createShndx()

    secHeadIndex = 0
    totalSections = len(gSecList)
    secHeadName = 'Elf32_SectionHeader'
    
    newSz = padInt(CUR_TEXT_SZ, 4)
    br.insert(CUR_TEXT_SZ, (newSz - CUR_TEXT_SZ) * '\x00')
    CUR_TEXT_SZ = newSz

    # if anywhere to use the section header offset, it is right here.
    SH_OFFSET=CUR_TEXT_SZ

    Elf32_SH_typeS = br.get_type_by_name(secHeadName)
    Elf32_SH_typeW = Elf32_SH_typeS.width
    br.insert(CUR_TEXT_SZ, (Elf32_SH_typeW * totalSections) * "\x00")
    
    curTempDataName = '__elf_section_headers'
    someVarThingSym = Symbol(SymbolType.DataSymbol, CUR_TEXT_SZ, curTempDataName)
    br.define_user_symbol(someVarThingSym)
    br.define_user_data_var(CUR_TEXT_SZ, Type.array(Elf32_SH_typeS, totalSections))

    CUR_TEXT_SZ += Elf32_SH_typeW * totalSections

    for curSec in gSecList:
        curVarAccessor = "{}[{}]".format(curTempDataName, secHeadIndex)
        shEntry(curVarAccessor, curSec, secHeadName)
        secHeadIndex += 1

    createSymStrTab()

def fillElfHeader(symFile):
    global CUR_TEXT_SZ
    global SH_OFFSET
    # print(hex(CUR_TEXT_SZ))
    createHeaderSection(TEXT_OFFSET)
    # print(hex(CUR_TEXT_SZ))
    parseSymFile(symFile)
    Elf32_Head_typeS = br.get_type_by_name("Elf32_Header")
    curTempDataName = '__elf_header'
    curHeadAddress = 0
    someVarThingSym = Symbol(SymbolType.DataSymbol, curHeadAddress, curTempDataName)
    br.define_user_symbol(someVarThingSym)
    br.define_user_data_var(curHeadAddress, Elf32_Head_typeS)
    patchStructMem(curTempDataName, b"\x7fELF", "ident", "signature")
    patchStructMem(curTempDataName, b"\x01", "ident", "file_class")
    patchStructMem(curTempDataName, b"\x01", "ident", "encoding")
    patchStructMem(curTempDataName, b"\x01", "ident", "version")
    patchStructMem(curTempDataName, b"\x61", "ident", "os")
    patchStructMem(curTempDataName, b"\x00", "ident", "abi_version")
    patchStructMem(curTempDataName, "ET_EXEC", "type")
    patchStructMem(curTempDataName, "EM_ARM", "machine")
    patchStructMem(curTempDataName, b"\x01", "version")
    netSize = getStructMemOff_netSize(curTempDataName, ['entry'])
    patchStructMem(curTempDataName, int.to_bytes(TEXT_ENTRY, byteorder='little', length=netSize), "entry")

    netSize = getStructMemOff_netSize(curTempDataName, ['program_header_offset'])
    pho = Elf32_Head_typeS.width
    patchStructMem(curTempDataName, int.to_bytes(pho, byteorder='little', length=netSize), "program_header_offset")

    patchStructMem(curTempDataName, "\x02\x06\x00\x00", "flags")

    netSize = getStructMemOff_netSize(curTempDataName, ['header_size'])
    patchStructMem(curTempDataName, int.to_bytes(pho, byteorder='little', length=netSize), "header_size")

    phs = br.get_type_by_name("Elf32_ProgramHeader").width
    phs = int.to_bytes(phs, byteorder='little', length=netSize)
    netSize = getStructMemOff_netSize(curTempDataName, ['program_header_size'])
    patchStructMem(curTempDataName, phs, "program_header_size")

    phoEntries = fillProgramHeader(pho)
    netSize = getStructMemOff_netSize(curTempDataName, ['program_header_count'])
    patchStructMem(curTempDataName, int.to_bytes(phoEntries, byteorder='little', length=netSize), "program_header_count")

    eSym = br.get_type_by_name("Elf32_SectionHeader").width
    netSize = getStructMemOff_netSize(curTempDataName, ['section_header_size'])
    patchStructMem(curTempDataName, int.to_bytes(eSym, byteorder='little', length=netSize), "section_header_size")

    shoEntries = fillSectionHeader()

    netSize = getStructMemOff_netSize(curTempDataName, ['section_header_offset'])
    patchStructMem(curTempDataName, int.to_bytes(SH_OFFSET, byteorder='little', length=netSize), "section_header_offset")

    netSize = getStructMemOff_netSize(curTempDataName, ['section_header_count'])
    patchStructMem(curTempDataName, int.to_bytes(len(gSecList), byteorder='little', length=netSize), "section_header_count")

    netSize = getStructMemOff_netSize(curTempDataName, ['string_table'])
    patchStructMem(curTempDataName, int.to_bytes(len(gSecList) - 3, byteorder='little', length=netSize), "string_table")

    print("finished")