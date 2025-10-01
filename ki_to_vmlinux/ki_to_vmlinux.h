#pragma once
#include <stdint.h>

int ki_to_vmlinux(const char* target_config, int target_arch, int endianess, size_t bitness_local, void* kernimgBase, size_t kernimgSz, const char* vmlinux_targ);

int pull_target_parameters(kern_static* targ_kern, const char* target_a);

