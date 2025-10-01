#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <vector>
#include <libgen.h>
#if defined(__linux__)
#include <linux/limits.h>
#else
#ifndef PATH_MAX
#define PATH_MAX 256
#endif
#endif

#include <localUtil.h>
#include <kern_static.h>
#include <drv_share.h>

#include <kernel_block.h>

#include "ki_to_vmlinux.h"

int usage(const char* name)
{
    fprintf(stderr, "Usage: %s [-o vmlinux_out] [-f family] [-d device] -j jsonconfig -m bitness -a arch -e endianess kernel_image\n",
        name);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int result = -1;
    const char* vmlinux_targ = 0;
    const char* kernimg_targ = 0;
    Elf64_Ehdr* vmlinuxBase = 0;
    char *kernimgBase = 0;
    size_t kernimgSz = 0;
    size_t vmlinux_sz;
    char vmlinux_dir_copy[PATH_MAX] = { 0 };
    std::string vmlinux_dir_made;

    kernel_symbol* ksymBase = 0;
    size_t ksymCount = 0;
    uint32_t* kcrcBase = 0;
    Elf64_Phdr* phdrBase = 0;

    const char* target_family = 0;
    const char* target_device = 0;
    const char* target_version = 0;
    const char* target_config = 0;

    int target_arch = 0;
    int endianess = 0;
    size_t bitness_local = 0;
    
    std::string* shstrtab_tmp;
    void* vmlinux_iter = 0;

    int opt = 0;

    const char* monitor = 0;

    while ((opt = getopt(argc, argv, "a:e:m:j:o:v:d:f:")) != -1)
    {
        switch (opt)
        {
        case 'a':
            if (strcmp(optarg, "armv7") == 0)
            {
                target_arch = EM_ARM;
                bitness_local = 32;
                endianess = ELFDATA2LSB;
            }
            else if (strcmp(optarg, "armv7eb") == 0)
            {
                target_arch = EM_ARM;
                bitness_local = 32;
                endianess = ELFDATA2MSB;
            }
            else if (strcmp(optarg, "aarch64") == 0)
            {
                target_arch = EM_AARCH64;
                bitness_local = 64;
                endianess = ELFDATA2LSB;
            }
            else if (strcmp(optarg, "ppc32") == 0)
            {
                target_arch = EM_PPC;
                bitness_local = 32;
                endianess = ELFDATA2MSB;
            }
            else if (strcmp(optarg, "ppc64") == 0)
            {
                target_arch = EM_PPC64;
                bitness_local = 64;
                endianess = ELFDATA2MSB;
            }
            else if (strcmp(optarg, "x86") == 0)
            {
                target_arch = EM_386;
                bitness_local = 32;
                endianess = ELFDATA2LSB;
            }
            else if (strcmp(optarg, "x86_64") == 0)
            {
                target_arch = EM_X86_64;
                bitness_local = 64;
                endianess = ELFDATA2LSB;
            }
            break;
        case 'e':
            if (strcmp(optarg, "little") == 0)
            {
                endianess = ELFDATA2LSB;
            }
            else if (strcmp(optarg, "big") == 0)
            {
                endianess = ELFDATA2MSB;
            }
            break;
        case 'm':
            bitness_local = atoi(optarg);
            break;
        case 'j':
            target_config = optarg;
            break;
        case 'o':
            vmlinux_targ = optarg;
            break;
        case 'v':
            target_version = optarg;
            break;
        case 'd':
            target_device = optarg;
            break;
        case 'f':
            target_family = optarg;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }
    
    if (optind < argc)
    {
        kernimg_targ = argv[optind];
        optind++;
    }

    if (kernimg_targ == 0)
    {
        usage(argv[0]);
    }

    if ((bitness_local != 64) && (bitness_local != 32))
    {
        usage(argv[0]);
    }

    if (vmlinux_targ == 0)
    {
        strcpy(vmlinux_dir_copy, kernimg_targ);
        dirname(vmlinux_dir_copy);
        vmlinux_dir_made = vmlinux_dir_copy;
        vmlinux_dir_made += "/vmlinux";
        vmlinux_targ = vmlinux_dir_made.data();
    }

    SAFE_BAIL(block_grab(kernimg_targ, (void**)&kernimgBase, &kernimgSz) == -1);

    SAFE_BAIL(ki_to_vmlinux(target_config, target_arch, endianess, bitness_local, kernimgBase, kernimgSz, vmlinux_targ) == -1);

    result = 0;
fail:
    SAFE_FREE(vmlinuxBase);
    return result;
}
