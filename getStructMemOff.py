import re

class bn_structRetriever:
    def __init__(self, bv, br):
        self.bv = bv
        self.br = br

    # check if the variable in question is an index variable, return
    # the variable base name and the index it is after.
    def getIndexObject(targetVar):
        potentialIndex = re.search(r"[\[\d\]]+", targetVar)
        targVarReal = targetVar
        if potentialIndex != None:
            potentialIndex = potentialIndex[0]
            targVarReal = targetVar.replace(potentialIndex, '')
            potentialIndex = potentialIndex.replace(']', '').replace('[', '')
            potentialIndex = int(potentialIndex)

        return targVarReal, potentialIndex

    def getRealStructType(self, structDesig):
        resStruct = None
        namedStruct = structDesig.get_string_before_name()
        if 'struct ' in namedStruct:
            resStruct = self.br.get_type_by_name(namedStruct.replace("struct ", ''))
        return resStruct

    def getRealEnumType(self, enumDesig):
        resEnum = None
        namedEnum = enumDesig.get_string_before_name()
        if 'enum ' in namedEnum:
            resEnum = self.br.get_type_by_name(namedEnum.replace("enum ", ''))
        return resEnum

    # potential ways to call
    # "__elf_program_headers[2]", "type"
    def getStructMemOff(self, targetVar, args):
        netOffset = 0
        netSize = 0
        targetVar, potentialIndex = self.getIndexObject(targetVar)
        targVarSym = self.br.get_symbol_by_raw_name(targetVar)
        targVarVar = self.br.get_data_var_at(targVarSym.address)
        if potentialIndex != None:
            nextTargVar = targVarVar.type.get_string_before_name()
            if 'struct ' in nextTargVar:
                nextTargVar = self.br.get_type_by_name(nextTargVar.replace("struct ", '')).structure
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
                curTargVarName, potentialIndex = self.getIndexObject(i)
                # for each member in the current struct being observed
                for eachMem in curTargVar.members:
                    # if the struct member's name is the target arg
                    if eachMem.name == curTargVarName:
                        if potentialIndex != None:
                            nextTargVar = targVarVar.type.get_string_before_name()
                            if 'struct ' in nextTargVar:
                                nextTargVar = self.br.get_type_by_name(nextTargVar.replace("struct ", ''))
                            else:
                                nextTargVar = targVarVar.type.element_type
                            netOffset += (nextTargVar.width * potentialIndex)
                        netOffset += eachMem.offset
                        netSize = eachMem.type.width
                        potStructType = self.getRealStructType(eachMem.type)
                        potEnumType = self.getRealEnumType(eachMem.type)
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

    def getStructMemOff_targAddr(self, targetVar, args):
        targAddr, _, _, _ = self.getStructMemOff(targetVar, args)
        return targAddr

    def getStructMemOff_netOffset(self, targetVar, args):
        _, netOffset, _, _ = self.getStructMemOff(targetVar, args)
        return netOffset

    def getStructMemOff_netSize(self, targetVar, args):
        _, _, netSize, _ = self.getStructMemOff(targetVar, args)
        return netSize

    def getStructMemOff_enumBool(self, targetVar, args):
        _, _, _, enumBool = self.getStructMemOff(targetVar, args)
        return enumBool

