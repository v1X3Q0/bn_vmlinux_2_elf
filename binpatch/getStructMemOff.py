import re

from binaryninja import TypeClass

class bn_structRetriever:
    def __init__(self, bv, br):
        self.bv = bv
        self.br = br

    # check if the variable in question is an index variable, return
    # the variable base name and the index it is after.
    def getIndexObject(self, targetVar):
        potentialIndex = re.search(r"[\[\d\]]+", targetVar)
        targVarReal = targetVar
        if potentialIndex != None:
            potentialIndex = potentialIndex[0]
            targVarReal = targetVar.replace(potentialIndex, '')
            potentialIndex = potentialIndex.replace(']', '').replace('[', '')
            potentialIndex = int(potentialIndex)

        return targVarReal, potentialIndex

    # if a struct, give back struct name. else, give back none
    def getRealStructType(self, structDesig):
        iterating_type = None
        iterating_type_prefix = structDesig.get_string_before_name()
        if (('struct' in iterating_type_prefix) or ('union' in iterating_type_prefix)) and (' ' not in iterating_type_prefix):
            print('found typeless {}'.format(iterating_type_prefix))
            iterating_type = structDesig
        else:
            if 'struct ' in iterating_type_prefix:
                iterating_type = self.bv.get_type_by_name(iterating_type_prefix.replace("struct ", ''))
            elif 'union ' in iterating_type_prefix:
                iterating_type = self.bv.get_type_by_name(iterating_type_prefix.replace("union ", ''))
        return iterating_type

    # if a enum, give back enum name. else, give back none
    def getRealEnumType(self, enumDesig):
        resEnum = None
        namedEnum = enumDesig.get_string_before_name()
        if 'enum ' in namedEnum:
            resEnum = self.bv.get_type_by_name(namedEnum.replace("enum ", ''))
        return resEnum

    def structArrFilter(self, potentialIndex, target_variable_instance, netOffset):
        iterating_type_prefix = target_variable_instance.type.get_string_before_name()
        # typeless structure or union, not enum
        if (('struct' in iterating_type_prefix) or ('union' in iterating_type_prefix)) and (' ' not in iterating_type_prefix):
            print('found typeless {}'.format(iterating_type_prefix))
            iterating_type = target_variable_instance
        # non typeless struct, get the juice
        else:            
            if 'struct ' in iterating_type_prefix:
                iterating_type = self.bv.get_type_by_name(iterating_type_prefix.replace("struct ", ''))
            elif 'union ' in iterating_type_prefix:
                iterating_type = self.bv.get_type_by_name(iterating_type_prefix.replace("union ", ''))
            else:
                # element type means its a primitive type, and get the base.
                iterating_type = target_variable_instance.type
        netOffset += (iterating_type.width * potentialIndex)
        # targVarVar.type.get_string_before_name()
        return iterating_type, netOffset

    # potential ways to call
    # "__elf_program_headers[2]", "type"
    def getStructMemOff(self, target_variable_name_whole, struct_member_rabbit_hole):
        """
        check a struct for if the member is in it, and return the offset/ballpark of type
        """
        netOffset = 0
        netSize = 0
        target_variable_name, potentialIndex = self.getIndexObject(target_variable_name_whole)
        target_variable_symbol = self.br.get_symbol_by_raw_name(target_variable_name)
        target_variable_instance = self.br.get_data_var_at(target_variable_symbol.address)

        # first, we need to see if object in question is an array with a provided index. if so,
        # go to that index
        if potentialIndex != None:
            iterating_type, netOffset = self.structArrFilter(potentialIndex, target_variable_instance, netOffset)
        # if not, get the structure being used, it will serve as our base for iteration
        else:
            iterating_type = target_variable_instance.type
        # if our type is just a reference to another type, we have to resolve it to its target.
        if iterating_type.type_class == TypeClass.NamedTypeReferenceClass:
            iterating_type = iterating_type.target(self.bv)
        enumBool = None
        if iterating_type != None:
            # iterate struct members
            for struct_member in struct_member_rabbit_hole:
                curTargVar = iterating_type
                cur_struct_member_name, potentialIndex = self.getIndexObject(struct_member)
                # for each member in the current struct being observed
                for eachMem in curTargVar.members:
                    # print('eachmen {}'.format(eachMem))
                    # if the struct member's name is the target arg
                    # pull the type into new iterating_type
                    if eachMem.name == cur_struct_member_name:
                        print('eachmen {}'.format(eachMem))
                        if eachMem.type.type_class == TypeClass.NamedTypeReferenceClass:
                            eachMem_type = eachMem.type.target(self.bv)
                        else:
                            eachMem_type = eachMem.type
                        if potentialIndex != None:
                            iterating_type, netOffset = self.structArrFilter(potentialIndex, eachMem_type, netOffset)
                        netOffset += eachMem.offset
                        netSize = eachMem_type.width
                        potStructType = self.getRealStructType(eachMem_type)
                        if potStructType != None:
                            iterating_type = potStructType
                            break
                        potEnumType = self.getRealEnumType(eachMem_type)
                        if potEnumType != None:
                            enumBool = potEnumType
                            break
                        # else it must be a primitive! stuff ends here, break out
                        break
        else:
            netSize = target_variable_instance.type.width
        # we have broken out, optimistically we are at the most primitive type
        # print("final width ", netSize)
        return target_variable_symbol.address, netOffset, netSize, enumBool

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

