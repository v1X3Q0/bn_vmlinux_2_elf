from binaryninja import SymbolType, types

KSYM_NAME_LEN = 128
kallsyms_requirements = ['kallsyms_token_table', 'kallsyms_token_index', 'kallsyms_names', 'kallsyms_num_syms']
kallsyms_optionals = ['kallsyms_offsets', 'kallsyms_addresses', 'kallsyms_relative_base']
class kallsyms_caller_t:
    def __init__(self, bv, kallsyms_req_dict):
        self.bv = bv
        self.kallsyms_token_table = kallsyms_req_dict['kallsyms_token_table']
        self.kallsyms_token_index = kallsyms_req_dict['kallsyms_token_index']
        self.kallsyms_names = kallsyms_req_dict['kallsyms_names']
        self.kallsyms_num_syms = kallsyms_req_dict['kallsyms_num_syms']
    def init_options(self, addresses, offsets, relative_base):
        self.kallsyms_addresses = addresses
        self.kallsyms_offsets = offsets
        self.kallsyms_relative_base = relative_base
    class kallsym:
        def __init__(self, namebuf, symtype, symaddress):
            self.namebuf = namebuf
            self.symtype = symtype
            self.symaddress = symaddress
    # /*
    #  * Get symbol type information. This is encoded as a single char at the
    #  * beginning of the symbol name.
    #  */
    def kallsyms_get_symbol_type(self, off):
        # /*
        # * Get just the first code, look it up in the token table,
        # * and return the first char from this token.
        # */
        kallsyms_names_dref = self.bv.read_int(self.kallsyms_names + off + 1, 1)
        kallsyms_token_index_dref = self.bv.read_int(self.kallsyms_token_index + kallsyms_names_dref * 2, 2)
        return self.bv.read_int(self.kallsyms_token_table + kallsyms_token_index_dref, 1)
        # return kallsyms_token_table[kallsyms_token_index[kallsyms_names[off + 1]]];
    # /*
    # * Expand a compressed symbol data into the resulting uncompressed string,
    # * if uncompressed string is too long (>= maxlen), it will be truncated,
    # * given the offset to where the symbol is in the compressed stream.
    # */
    def kallsyms_expand_symbol(self, off, maxlen):
        len = 0
        skipped_first = 0
        tptr = 0
        data = 0
        result = ''
        # /* Get the compressed symbol length from the first symbol byte. */
        data = self.kallsyms_names + off
        len = int.from_bytes(self.bv.read(data, 1), 'little')
        data += 1
        # /*
        # * Update the offset to return the offset for the next symbol on
        # * the compressed stream.
        # */
        off += len + 1
        # /*
        # * For every byte on the compressed symbol data, copy the table
        # * entry for that byte.
        # */
        while len != 0:
            data_dref = int.from_bytes(self.bv.read(data, 1), 'little')
            kallsyms_token_index_dref = int.from_bytes(self.bv.read(self.kallsyms_token_index + data_dref * 2, 2), 'little')
            tptr = self.kallsyms_token_table + kallsyms_token_index_dref
            tptr_dref = int.from_bytes(self.bv.read(tptr, 1), 'little')
            # tptr = &kallsyms_token_table[kallsyms_token_index[*data]];
            data += 1
            len -= 1
            while tptr_dref != 0:
                if skipped_first != 0:
                    if maxlen <= 1:
                        return result, off
                    result += chr(tptr_dref)
                    maxlen -= 1
                else:
                    skipped_first = 1
                tptr += 1
                tptr_dref = int.from_bytes(self.bv.read(tptr, 1), 'little')
        # /* Return to offset to the next symbol. */
        return result, off
    def kallsyms_get_sym_addr(self, index):
        if self.kallsyms_addresses != None:
            addrbase = self.kallsyms_addresses
            symaddress = self.bv.read_pointer(addrbase + index * self.bv.address_size)
        else:
            addrbase = self.kallsyms_offsets
            symoffset = self.bv.read_int(addrbase + index * 4, 4, True)
            if symoffset >= 0:
                symaddress = self.kallsyms_relative_base + symoffset
            else:
                symaddress = self.kallsyms_relative_base - 1 - symoffset
        return symaddress
    # /* Lookup the address for this symbol. Returns 0 if not found. */
    def kallsyms_lookup_name(self, name):
        namebuf = ''
        off = 0
        numsyms = self.bv.read_int(self.kallsyms_num_syms, self.bv.address_size)
        for i in range(0, numsyms):
            namebuf, off = self.kallsyms_expand_symbol(off, KSYM_NAME_LEN)
            symaddress = self.kallsyms_get_sym_addr(i)
            print("found sym {}, off was {} of {}, symtype {} symaddr {}\n".format(namebuf, off, numsyms,
                chr(self.kallsyms_get_symbol_type(off)), hex(symaddress)))
            if namebuf == name:
                print("found target sym, off was {} of {}, symtype {} symaddr {}\n".format(off, numsyms,
                    chr(self.kallsyms_get_symbol_type(off)), hex(symaddress)))
                return 0
        # // return module_kallsyms_lookup_name(name);
        return -1
    def maybedef_var(self, varname, varaddr, vartype=SymbolType.FunctionSymbol):
        vartmp = self.bv.get_functions_by_name(varname)
        if len(vartmp) != 0:
            return
        newsym = types.Symbol(vartype, varaddr, "{}".format(varname))
        self.bv.define_user_symbol(newsym)        
        return
    def kallsyms_resolve_all(self, resolvecount=None):
        kallsyms_net = []
        off = 0
        if resolvecount == None:
            toresolve = self.bv.read_int(self.kallsyms_num_syms, self.bv.address_size)
        else:
            toresolve = resolvecount
        for i in range(0, toresolve):
            namebuf, off = self.kallsyms_expand_symbol(off, KSYM_NAME_LEN)
            symtype = chr(self.kallsyms_get_symbol_type(off))
            symaddress = self.kallsyms_get_sym_addr(i)
            kallsyms_net.append(self.kallsym(namebuf, symtype, symaddress))
            if i < 5000:
                if (i % 1000) == 0:
                    print('found {} symbols'.format(i))
        return kallsyms_net
    def kallsyms_name_all(self, kallsyms_net):
        for each_func in kallsyms_net:
            self.maybedef_var(each_func.namebuf, each_func.symaddress)
def fillkallsyms(bv):
    print("beginning fillkallsyms")
    kallsyms_req_dict = {}
    for kallsyms_requirement in kallsyms_requirements:
        # if bv.symbols[kallsyms_requirement] == None:
        #     print('missing symbol {}'.format(kallsyms_requirement))
        kallsyms_req_dict[kallsyms_requirement] = bv.symbols[kallsyms_requirement][0].address
    for i in kallsyms_req_dict.keys():
        print('{}: {}'.format(i, hex(kallsyms_req_dict[i])))
    kallsyms_caller = kallsyms_caller_t(bv, kallsyms_req_dict)
    if ('kallsyms_addresses' in bv.symbols) == True:
        addrtmp = bv.symbols['kallsyms_addresses'][0].address
        kallsyms_caller.init_options(addrtmp, None, None)
    else:
        addrtmp = bv.symbols['kallsyms_offsets'][0].address
        if ('kallsyms_relative_base' in bv.symbols) == True:
            rel = bv.read_pointer(bv.symbols['kallsyms_relative_base'][0].address)
        else:
            rel = bv.start
        kallsyms_caller.init_options(None, addrtmp, rel)
    kallsyms_net = kallsyms_caller.kallsyms_resolve_all()
    kallsyms_caller.kallsyms_name_all(kallsyms_net)
    return kallsyms_caller
