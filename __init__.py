from .binpatch.genElfHeader import genElfHeader
from .binpatch.kallsym import fillkallsyms
from .bn_raw_elf_fill.add_header_binaryninja import add_header_p
from binaryninja import PluginCommand

PluginCommand.register("addHeader", "import header", add_header_p)
PluginCommand.register("genElfHeader", "generate elf header for vmlinux", genElfHeader)
PluginCommand.register("fillkallsyms", "fill elf header with kallsyms if it has necessar 5", fillkallsyms)