from .genElfHeader import genElfHeader
from .kallsym import fillkallsyms
from binaryninja import PluginCommand

PluginCommand.register("genElfHeader", "generate elf header for vmlinux", genElfHeader)
PluginCommand.register("fillkallsyms", "fill elf header with kallsyms if it has necessar 5", fillkallsyms)