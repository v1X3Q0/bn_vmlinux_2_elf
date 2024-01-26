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
