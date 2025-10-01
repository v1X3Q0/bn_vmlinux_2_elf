class elfSymbol:
    def __init__(self, symName=0, symNameOff=0, symValue=0, symType=0, symBind=0, symOther=0, symShndx=0):
        self.symName = symName
        self.symNameOff = symNameOff
        self.symValue = symValue
        self.symType = symType
        self.symBind = symBind
        self.symOther = symOther
        self.symShndx = symShndx

class elfShndxEnt:
    def __init__(self, name, address, size):
        self.name = name
        self.address = address
        self.size = size

class elfSection:
    def __init__(self, name='', secNameOff=0, secType=0, secFlags=0, secAddr=0, secOffset=0, secSize=0, secLink=0, secInfo=0, secAlign=0, secEntsz=0):
        self.name = name
        self.secNameOff = secNameOff
        self.secType = secType
        self.secFlags = secFlags
        self.secAddr = secAddr
        self.secOffset = secOffset
        self.secSize = secSize
        self.secLink = secLink
        self.secInfo = secInfo
        self.secAlign = secAlign
        self.secEntsz = secEntsz

class elfSegment:
    def __init__(self, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align
