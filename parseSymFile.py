from .pyelf import elfSection, elfShndxEnt, elfSymbol

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

gSecList = []
gSymList = []
gShndxRaw = '\x00'
gStrRaw = '\x00'

OG_TEXT_SZ = br.length
CUR_TEXT_SZ = OG_TEXT_SZ
TEXT_OFFSET = 0x18000

def parseSymFile(symFile, symStart='stext', symEnd='_etext'):
    global TEXT_ENTRY
    global TEXT_END
    global OG_TEXT_SZ
    global CUR_TEXT_SZ
    global gSymList
    global gShndxRaw
    global gStrRaw
    global gSecList

    if symFile == None:
        return
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

