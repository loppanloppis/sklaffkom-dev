#define LOGTAG "door"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "sklaff.h"
#include "ext_globals.h"
#include "door.h"

static int
current_node(void)
{
    int fd;
    int node = 0;
    char *buf, *oldbuf, *ptr;
    struct ACTIVE_ENTRY ae;

    fd = open_file(ACTIVE_FILE, 0);
    if (fd == -1)
        return 0;

    buf = read_file(fd);

    if (close_file(fd) == -1) {
        if (buf)
            free(buf);
        return 0;
    }

    if (buf == NULL)
        return 0;

    oldbuf = buf;
    ptr = buf;

    while (ptr && *ptr) {
        ptr = get_active_entry(ptr, &ae);

        if (ae.user == Uid &&
            ae.pid == (int)getpid()) {
            node = ae.node;
            break;
        }
    }

    free(oldbuf);
    return node;
}

static int
build_dropfile_info(struct dropfile_info *info)
{
    LINE name;
    int node;

    memset(info, 0, sizeof(*info));

    node = current_node();
    if (node <= 0)
        return -1;

    if (user_name(Uid, name) == NULL)
        return -1;

    info->uid = Uid;
    info->node = node;

    /*
     * SklaffKOM doesn't currently have classic BBS security levels
     * or a total session time limit.
     */
    info->security = 100;
    info->time_left = 999;
    info->ansi = 1;

    strlcpy(info->name, name, sizeof(info->name));
    strlcpy(info->handle, name, sizeof(info->handle));

    strlcpy(info->bbs_name, SKLAFF_ID,
        sizeof(info->bbs_name));

    snprintf(info->bbs_software,
        sizeof(info->bbs_software),
        "SklaffKOM %s",
        sklaff_version ? sklaff_version : "");

    strlcpy(info->sysop, SKLAFF_SYSOP,
        sizeof(info->sysop));

    return 0;
}

int
run_door(const char *workdir,
    const char *program,
    enum dropfile_type type,
    const char *dropfile_option)
{
    char tempdir[] = "/tmp/sklaff-door-XXXXXX";
    char dropfile[PATH_MAX];
    char cwd[PATH_MAX];
    struct dropfile_info info;
    int ret;

    if (build_dropfile_info(&info) == -1) {
        output("\nKan inte skapa sessionsinformation f|r door.\n\n");
        return -1;
    }

    if (mkdtemp(tempdir) == NULL) {
        output("\nKan inte skapa tempor{r door-katalog.\n\n");
        return -1;
    }

    if (write_dropfile(type, tempdir, &info,
            dropfile, sizeof(dropfile)) == -1) {
        output("\nKan inte skapa dropfil.\n\n");
        rmdir(tempdir);
        return -1;
    }

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        unlink(dropfile);
        rmdir(tempdir);
        return -1;
    }

    /*
     * Some doors, including uMRC, expect configuration/resources
     * relative to their own installation directory.
     */
    if (chdir(workdir) == -1) {
        output("\nKan inte g} till door-katalogen: %s\n\n",
            workdir);
        unlink(dropfile);
        rmdir(tempdir);
        return -1;
    }

    if (dropfile_option && *dropfile_option) {
        const char *argv[] = {
            program,
            dropfile_option,
            dropfile,
            NULL
        };

        ret = run_external_cmd_args(argv, 0);
    } else {
        const char *argv[] = {
            program,
            NULL
        };

        ret = run_external_cmd_args(argv, 0);
    }

    if (chdir(cwd) == -1) {
        output("\nVarning: kunde inte }terst{lla arbetskatalogen.\n");
    }

    unlink(dropfile);
    rmdir(tempdir);

    return ret;
}
