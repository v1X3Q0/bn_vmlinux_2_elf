from .genElfHeader import genElfHeader
from binaryninja import PluginCommand

PluginCommand.register("genElfHeader", "generate elf header for vmlinux", genElfHeader)