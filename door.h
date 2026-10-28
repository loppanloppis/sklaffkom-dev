#ifndef SKLAFF_DOOR_H
#define SKLAFF_DOOR_H

#include "dropfile.h"

int run_door(const char *workdir,
    const char *program,
    enum dropfile_type type,
    const char *dropfile_option);

#endif
