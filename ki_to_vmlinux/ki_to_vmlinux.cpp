#include <stdio.h>

#include <localUtil.h>
#include <kern_static.h>

#include <kernel_block.h>

#include "ki_to_vmlinux.h"

void progHeadConstruction(Elf64_Phdr* phHead, size_t imageSz)
{
    memset(phHead, 0, sizeof(Elf64_Phdr));
    phHead->p_type = PT_LOAD;
    phHead->p_flags = PF_X | PF_W | PF_R;
    phHead->p_offset = PAGE_SIZE4K;
    phHead->p_vaddr = ANDROID_KERNBASE;
    phHead->p_paddr = ANDROID_KERNBASE;
    phHead->p_filesz = imageSz;
    phHead->p_memsz = imageSz;
    phHead->p_align = 0x10000;
}


int ki_to_vmlinux(const char* target_config, int target_arch, int endianess, size_t bitness_local, void* kernimgBase, size_t kernimgSz, const char* vmlinux_targ)
{
    int result = -1;
    FILE* out_vmlinux = 0;
    kern_static* parsedKernimg = 0;
    void* vmlinuxBase = 0;
    size_t vmlinux_sz = 0;

    parsedKernimg = new kern_static(kernimgBase, kernimgSz, bitness_local, target_arch, endianess);
    parsedKernimg->parseAndGetGlobals();
    
    if (target_config != 0)
    {
        pull_target_parameters(parsedKernimg, target_config);
    }
    
    parsedKernimg->elfConstruction();

    out_vmlinux = fopen(vmlinux_targ, "w");
    SAFE_BAIL(out_vmlinux == 0);
    fwrite(vmlinuxBase, 1, vmlinux_sz, out_vmlinux);

    printf("created new vmlinux %s\n", vmlinux_targ);

    result = 0;
fail:
    SAFE_FCLOSE(out_vmlinux);
    SAFE_DEL(parsedKernimg);
    return result;
}