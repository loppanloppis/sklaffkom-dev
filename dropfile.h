#ifndef SKLAFF_DROPFILE_H
#define SKLAFF_DROPFILE_H

#include <stddef.h>

enum dropfile_type {
    DROPFILE_DOOR32 = 1,
    DROPFILE_DOORSYS
};

struct dropfile_info {
    int uid;
    int node;
    int security;
    int time_left;
    int ansi;

    char name[128];
    char handle[128];

    /*
     * Not needed by DOOR32.SYS, but useful when we add
     * DOOR.SYS and DORINFOx.DEF later.
     */
    char bbs_name[128];
    char bbs_software[128];
    char sysop[128];
    char location[128];
};

int write_dropfile(enum dropfile_type type,
    const char *dir,
    const struct dropfile_info *info,
    char *path,
    size_t path_size);

#endif
