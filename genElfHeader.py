import re

br = bv.get_view_of_type('Raw')
TEXT_OFFSET = 0x18000
CUR_TEXT_SZ = len(br)
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
    print("final width ", netSize)
    return targVarSym.address, netOffset, netSize, enumBool

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
            print("wrong size?!?!?", len(toWrite), netSize)
            return -1
    if enumBool != None:
        annotateEnum = toWrite.split(' | ')
        enumValue = 0
        for i in annotateEnum:
            enumValue = enumValue | getEnumValue(enumBool, i)
        toWrite = int.to_bytes(enumValue, byteorder='little', length=netSize)
    retValue = br.write(targAddr + netOffset, toWrite)
    return retValue

def fetchStructMem(targetVar, *args):
    targAddr, netOffset, netSize, enumBool = getStructMemOff(targetVar, args)
    retValue = br.read(targAddr + netOffset, netSize)
    return retValue

def createHeaderSection(initPadding):
    br.insert(0, initPadding * '\x00')

def phEntry(phOff, p_type, offset, virtual_address, physical_address, file_size, memory_size, flags, align):
    patchStructMem(phOff, p_type, 'type')
    targAddr, netOffset, netSize, enumBool = getStructMemOff(phOff, ['offset'])
    patchStructMem(phOff, int.to_bytes(offset, byteorder='little', length=netSize), 'offset')
    targAddr, netOffset, netSize, enumBool = getStructMemOff(phOff, ['virtual_address'])
    patchStructMem(phOff, int.to_bytes(virtual_address, byteorder='little', length=netSize), 'virtual_address')
    targAddr, netOffset, netSize, enumBool = getStructMemOff(phOff, ['physical_address'])
    patchStructMem(phOff, int.to_bytes(physical_address, byteorder='little', length=netSize), 'physical_address')
    targAddr, netOffset, netSize, enumBool = getStructMemOff(phOff, ['file_size'])
    patchStructMem(phOff, int.to_bytes(file_size, byteorder='little', length=netSize), 'file_size')
    targAddr, netOffset, netSize, enumBool = getStructMemOff(phOff, ['memory_size'])
    patchStructMem(phOff, int.to_bytes(memory_size, byteorder='little', length=netSize), 'memory_size')
    patchStructMem(phOff, flags, 'flags')
    targAddr, netOffset, netSize, enumBool = getStructMemOff(phOff, ['align'])
    patchStructMem(phOff, int.to_bytes(align, byteorder='little', length=netSize), 'align')

def fillProgramHeader(pho):
    result = -1
    Elf32_PH_typeS = br.get_type_by_name("Elf32_ProgramHeader")
    curTempDataName = "__elf_program_headers"
    someVarThingSym = Symbol(SymbolType.DataSymbol, pho, curTempDataName)
    br.define_user_symbol(someVarThingSym)
    br.define_user_data_var(pho, Type.array(Elf32_PH_typeS, 1))
    entryIndex = 0
    phEntry('{}[{}]'.format(curTempDataName, entryIndex), "PT_LOAD", TEXT_OFFSET,
        TEXT_ENTRY, TEXT_ENTRY, CUR_TEXT_SZ, CUR_TEXT_SZ, "PF_X | PF_W | PF_R",
        0x10000)
    return entryIndex

class elfSymbol:
    def __init__(self, symAddr, symType, symName):
        self.symAddr = symAddr
        self.symType = symType
        self.symName = symName

class elfSection:
    def __init__(self, secAddr, secSize, secName, secOffset):
        self.secAddr = secAddr
        self.secSize = secSize
        self.secName = secName
        self.secOffset = secOffset

def parseSymFile(symFile, symStart='stext', symEnd='_etext'):
    global TEXT_ENTRY
    global TEXT_END
    f = open(symFile, "r")
    g = f.readlines()
    f.close()
    symList = []
    activeParsing=False
    for i in g:
        i = i.replace('\n', '')
        lineDexed = i.split(' ')
        curElfSymbol = elfSymbol(int(lineDexed[0], 0x10), lineDexed[1], lineDexed[2])
        if curElfSymbol.symName == symStart:
            TEXT_ENTRY = curElfSymbol.symAddr
            activeParsing=True
        elif curElfSymbol.symName == symEnd:
            TEXT_END = curElfSymbol.symAddr
            activeParsing=False
        if activeParsing == True:
            symList.append(curElfSymbol)            
        # if curElfSymbol.symName in SYM_SECTLIST.keys():
    return symList

def createSynStrTab(symbolList):
    curTempDataName = "Elf32_Sym"
    symTabRaw = ""
    strTabRaw = ""
    symTabRef = 0
    for i in symbolList:
        curLen = i.symName + '\x00'
        strTabRaw += curLen
        # name
        targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['name'])
        symTabRaw += int.to_bytes(symTabRef, byteorder='little', length=netSize)
        # value
        targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['value'])
        symTabRaw += int.to_bytes(i.symAddr, byteorder='little', length=netSize)
        # size
        targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['size'])
        symTabRaw += int.to_bytes(0, byteorder='little', length=netSize)
        # info
        targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['info'])
        symTabRaw += int.to_bytes(0, byteorder='little', length=netSize)
        # other
        targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['other'])
        symTabRaw += int.to_bytes(0, byteorder='little', length=netSize)
        # shndx
        targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['shndx'])
        symTabRaw += int.to_bytes(0, byteorder='little', length=netSize)
        symTabRef += len(curLen)
    return symTabRaw, strTabRaw

def createSecHead(symbolList):
    shndxRaw = "\x00"
    elfSecRaw = ""
    curTempDataName = 'Elf32_SectionHeader'
    elfSecRef = len(shndxRaw)
    secList = []
    secListIndex = 0
    secCur = 0
    for i in symbolList:
        if i.symNmae in SYM_SECTLIST.keys():
            curLen = i.symName + '\x00'
            shndxRaw += curLen
            # name
            targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['name'])
            elfSecRaw += int.to_bytes(elfSecRef, byteorder='little', length=netSize)
            # type
            targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['type'])
            elfSecRaw += int.to_bytes(elfSecRef, byteorder='little', length=netSize)
            # ...
            # address
            targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['address'])
            elfSecRaw += int.to_bytes(i.symAddr, byteorder='little', length=netSize)

            offReal = (i.symAddr - TEXT_ENTRY) + TEXT_OFFSET
            secSize = offReal - secCur
            curSecTmp = elfSection(i.symAddr, 0, i.symName, offReal)
            
            if len(secList) > 0:
                secList[len(secList) - 1].secSize = offReal - secCur

            secCur = offReal
            elfSecRef += len(curLen)


def createShndx(symbolList):
    shndxRaw = "\x00"
    for i in SYM_SECTLIST.keys():
        shndxRaw += i + '\x00'

# it should be .shstrtab
# section header
# symtab
# strtab

def fillSectionHeader(sho):
    result = -1
    symFile
    if symFile == None:
        return result
    symbolList = parseSymFile(symFile)
    shndxTab = createShndx(symbolList)
    secHead = createSecHead(symbolList)
    symTabRaw, strTabRaw = createStrTab(symbolList)
    br.insert()

def fillElfHeader():
    symFile
    parseSymFile(symFile)
    createHeaderSection(TEXT_OFFSET)
    Elf32_Head_typeS = br.get_type_by_name("Elf32_Header")
    curTempDataName = '__elf_header'
    curHeadAddress = 0
    curTextSize = CUR_TEXT_SZ + TEXT_OFFSET
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
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['entry'])
    patchStructMem(curTempDataName, int.to_bytes(TEXT_ENTRY, byteorder='little', length=netSize), "entry")
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['program_header_offset'])
    pho = Elf32_Head_typeS.width
    # phoRaw = int.to_bytes(pho, byteorder='little', length=netSize)
    patchStructMem(curTempDataName, int.to_bytes(pho, byteorder='little', length=netSize), "program_header_offset")
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['section_header_offset'])
    # sho = int.to_bytes(curTextSize, byteorder='little', length=netSize)
    patchStructMem(curTempDataName, int.to_bytes(curTextSize, byteorder='little', length=netSize), "section_header_offset")
    patchStructMem(curTempDataName, "\x02\x06\x00\x00", "flags")
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['header_size'])
    patchStructMem(curTempDataName, int.to_bytes(pho, byteorder='little', length=netSize), "header_size")
    phs = br.get_type_by_name("Elf32_ProgramHeader").width
    phs = int.to_bytes(phs, byteorder='little', length=netSize)
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['program_header_size'])
    patchStructMem(curTempDataName, phs, "program_header_size")
    phoEntries = fillProgramHeader(pho)
    eSym = br.get_type_by_name("Elf32_Sym").width
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['section_header_size'])
    patchStructMem(curTempDataName, int.to_bytes(eSym, byteorder='little', length=netSize), "section_header_size")
    shoEntries = fillSectionHeader()
    targAddr, netOffset, netSize, enumBool = getStructMemOff(curTempDataName, ['section_header_count'])
    patchStructMem(curTempDataName, int.to_bytes(0xd, byteorder='little', length=netSize), "section_header_count")
