#pragma once
#include <stdint.h>

int ki_to_vmlinux(int target_arch, int endianess, size_t bitness_local, void* kernimgBase, size_t kernimgSz, const char* vmlinux_targ);