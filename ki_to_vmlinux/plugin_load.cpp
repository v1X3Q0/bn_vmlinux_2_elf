#include <string>
#include <stdio.h>
#include <json.h>
#include <localUtil.h>
#include <elf.h>
#include <kern_img.h>
#include <kern_static.h>

int pull_target_parameters(kern_static *targ_kern, const char *target_a)
{
    int result = -1;

    // jsmntok_t t[128]; /* We expect no more than 128 JSON tokens */
    // jsmn_parser p;

    json_object *jobj = 0;

    char *json_block = 0;
    size_t json_block_sz = 0;
    lh_entry *tmpent = 0;
    lh_entry *internaldef = 0;
    lh_table *tmptab = 0;
    lh_table *internaltab = 0;
    json_object *parsed_segments = 0;
    json_object *parsed_sections = 0;
    json_object *explicitft = 0;
    const char *internalval = 0;
    const char *segtemp = 0;
    const char *sectemp = 0;

    SAFE_BAIL(target_a == 0);

    SAFE_BAIL(block_grab(target_a, (void **)&json_block, &json_block_sz) != 0);

    jobj = json_tokener_parse(json_block);

    // populate segments
    parsed_segments = json_object_object_get(jobj, "segments");
    if (parsed_segments != 0)
    {
        tmptab = json_object_get_object(parsed_segments);
        if (tmptab != 0)
        {
            tmpent = tmptab->head;
            for (int i = 0; i < tmptab->count; i++)
            {
                //                    don't need a name, but reference it for posterity's sake
                segtemp = (const char *)tmpent->k;
                internaltab = json_object_get_object((const struct json_object *)tmpent->v);
                if (internaltab != 0)
                {
                    int prot = 0;
                    uint64_t Virtual = 0;
                    uint64_t Physical = 0;
                    uint64_t FileOffset = 0;
                    uint64_t size = 0;
                    internaldef = internaltab->head;

                    for (int j = 0; j < internaltab->count; j++)
                    {
                        internalval = json_object_get_string((struct json_object *)internaldef->v);
                        std::string internaldefk = std::string((const char *)internaldef->k);
                        std::string internalvals = std::string((const char *)internalval);
                        if (internaldefk == "permissions")
                        {
                            if (internalvals.find("r") != -1)
                            {
                                prot |= PF_R;
                            }
                            if (internalvals.find("w") != -1)
                            {
                                prot |= PF_W;
                            }
                            if (internalvals.find("x") != -1)
                            {
                                prot |= PF_X;
                            }
                        }
                        else if (internaldefk == "Virtual")
                        {
                            Virtual = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        else if (internaldefk == "Physical")
                        {
                            Physical = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        else if (internaldefk == "FileOffset")
                        {
                            FileOffset = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        //                            else if (internaldefk == "fileback")
                        //                            {
                        //
                        //                            }
                        else if (internaldefk == "size")
                        {
                            size = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        internaldef = internaldef->next;
                    }
                    targ_kern->insert_elfsegment(segtemp, prot, Virtual, Physical, FileOffset, size);
                    //                        we have a complete segment, construct and iterate next
                }
                tmpent = tmpent->next;
            }
        }
    }

    // popoulate sections
    parsed_sections = json_object_object_get(jobj, "sections");
    if (parsed_segments != 0)
    {
        tmptab = json_object_get_object(parsed_sections);
        if (tmptab != 0)
        {
            tmpent = tmptab->head;
            for (int i = 0; i < tmptab->count; i++)
            {
                sectemp = (const char *)tmpent->k;
                internaltab = json_object_get_object((const struct json_object *)tmpent->v);
                if (internaltab != 0)
                {
                    internaldef = internaltab->head;
                    uint64_t Virtual = 0;
                    uint64_t FileOffset = 0;
                    uint64_t size = 0;
                    for (int j = 0; j < internaltab->count; j++)
                    {
                        internalval = json_object_get_string((struct json_object *)internaldef->v);
                        std::string internaldefk = std::string((const char *)internaldef->k);
                        std::string internalvals = std::string((const char *)internalval);
                        if (internaldefk == "Virtual")
                        {
                            Virtual = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        else if (internaldefk == "FileOffset")
                        {
                            FileOffset = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        else if (internaldefk == "size")
                        {
                            size = strtoull(internalvals.c_str(), NULL, 0x10);
                        }
                        internaldef = internaldef->next;
                    }
                    targ_kern->insert_elfsection(sectemp, Virtual, FileOffset, size);
                    //                        we have a complete segment, construct and iterate next
                }
                tmpent = tmpent->next;
            }
        }
    }

    explicitft = json_object_object_get(jobj, "filetype");
    if (explicitft != 0)
    {
        std::string filetypespec = std::string(json_object_get_string(explicitft));
        void *dynmod = dlopen(filetypespec.c_str(), RTLD_NOW);
        int (*parseandgetoffsets_extc)(void *) = (int (*)(void *))dlsym(dynmod, "parseandgetoffsets_extc");
        parseandgetoffsets_extc(targ_kern);
        dlclose(dynmod);
    }

    result = 0;
fail:
    SAFE_FREE(json_block);
    return result;
}

// void thing()
// {
//         // parse the json and determine which sorters/generators i need to run
//     if (target_family_a != 0)
//     {
//         target_family = target_family_a;
//         json_file = fopen((target_family + ".json").c_str(), "r");

//         fseek(json_file, 0, SEEK_END);
//         json_block_sz = ftell(json_file);
//         fseek(json_file, 0, SEEK_SET);

//         json_block = (char *)malloc(json_block_sz);
//         fread(json_block, 1, json_block_sz, json_file);

//         jobj = json_tokener_parse(json_block);

//         // jsmn_init(&p);
//         // jsmn_parse(&p, json_block, json_block_sz, t, 128); // "s" is the char array holding the json content

//         dlopen(("lib" + target_family + ".so").c_str(), RTLD_NOW);
//     }

//     if (target_device_a != 0)
//     {
//         target_device = target_device_a;
//         fopen((target_device + ".json").c_str(), "r");
//         dlopen(("lib" + target_device + ".so").c_str(), RTLD_NOW);
//     }

// }
