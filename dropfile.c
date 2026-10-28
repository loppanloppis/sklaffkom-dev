#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include "dropfile.h"

static int
write_door32(const char *dir,
    const struct dropfile_info *info,
    char *path,
    size_t path_size)
{
    FILE *fp;

    if (snprintf(path, path_size, "%s/DOOR32.SYS", dir) >=
        (int)path_size)
        return -1;

    fp = fopen(path, "w");
    if (fp == NULL)
        return -1;

    /*
     * DOOR32.SYS revision 1
     *
     *  1  communication type (0 = local)
     *  2  socket/handle
     *  3  baud rate
     *  4  BBS software/version
     *  5  user record number
     *  6  real name
     *  7  handle/alias
     *  8  security level
     *  9  minutes remaining
     * 10  terminal emulation (1 = ANSI)
     * 11  node number
     */
    if (fprintf(fp,
            "0\n"
            "0\n"
            "0\n"
            "%s\n"
            "%d\n"
            "%s\n"
            "%s\n"
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n",
            info->bbs_software,
            info->uid,
            info->name,
            info->handle,
            info->security,
            info->time_left,
            info->ansi,
            info->node) < 0) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0)
        return -1;

    return 0;
}

static int
write_doorsys(const char *dir,
    const struct dropfile_info *info,
    char *path,
    size_t path_size)
{
    FILE *fp;
    time_t now;
    struct tm tm_now;
    char call_time[16];
    int minutes;
    int seconds;

    if (snprintf(path, path_size, "%s/DOOR.SYS", dir) >=
        (int)path_size)
        return -1;

    /*
     * Classic DOOR.SYS contains time remaining both in seconds
     * and minutes. 546 minutes is a useful upper bound because
     * 546 * 60 = 32760, which still fits in a signed 16-bit value.
     */
    minutes = info->time_left;

    if (minutes < 0)
        minutes = 0;
    if (minutes > 546)
        minutes = 546;

    seconds = minutes * 60;

    now = time(NULL);

    if (localtime_r(&now, &tm_now) == NULL) {
        strcpy(call_time, "00:00");
    } else {
        strftime(call_time, sizeof(call_time), "%H:%M", &tm_now);
    }

    /*
     * Use binary mode so that the CR/LF written below remains exact
     * on platforms where text mode performs newline translation.
     */
    fp = fopen(path, "wb");
    if (fp == NULL)
        return -1;

    /*
     * Full 52-line DOOR.SYS.
     *
     * Unknown or inapplicable fields are deliberately left blank
     * or zero rather than inventing user data.
     */

    fprintf(fp, "COM0:\r\n");                         /*  1 Port */
    fprintf(fp, "0\r\n");                             /*  2 Effective baud */
    fprintf(fp, "8\r\n");                             /*  3 Data bits */
    fprintf(fp, "%d\r\n", info->node);                /*  4 Node */
    fprintf(fp, "0\r\n");                             /*  5 Locked baud */
    fprintf(fp, "Y\r\n");                             /*  6 Screen display */
    fprintf(fp, "N\r\n");                             /*  7 Printer */
    fprintf(fp, "Y\r\n");                             /*  8 Page bell */
    fprintf(fp, "Y\r\n");                             /*  9 Caller alarm */

    fprintf(fp, "%s\r\n", info->name);                /* 10 User name */
    fprintf(fp, "%s\r\n", info->location);            /* 11 Location */
    fprintf(fp, "\r\n");                              /* 12 Home phone */
    fprintf(fp, "\r\n");                              /* 13 Work phone */
    fprintf(fp, "\r\n");                              /* 14 Password */
    fprintf(fp, "%d\r\n", info->security);            /* 15 Security */
    fprintf(fp, "0\r\n");                             /* 16 Number of calls */
    fprintf(fp, "\r\n");                              /* 17 Last call date */
    fprintf(fp, "%d\r\n", seconds);                   /* 18 Seconds left */
    fprintf(fp, "%d\r\n", minutes);                   /* 19 Minutes left */

    fprintf(fp, "%s\r\n", info->ansi ? "GR" : "NG");  /* 20 Graphics */
    fprintf(fp, "24\r\n");                            /* 21 Screen length */
    fprintf(fp, "N\r\n");                             /* 22 Expert mode */
    fprintf(fp, "\r\n");                              /* 23 Conferences */
    fprintf(fp, "\r\n");                              /* 24 Last conference */
    fprintf(fp, "\r\n");                              /* 25 Expiration date */

    fprintf(fp, "%d\r\n", info->uid);                 /* 26 User record */
    fprintf(fp, "\r\n");                              /* 27 Protocol */
    fprintf(fp, "0\r\n");                             /* 28 Uploads */
    fprintf(fp, "0\r\n");                             /* 29 Downloads */
    fprintf(fp, "0\r\n");                             /* 30 Daily KB */
    fprintf(fp, "0\r\n");                             /* 31 Daily KB limit */

    fprintf(fp, "\r\n");                              /* 32 Birth date */
    fprintf(fp, "\r\n");                              /* 33 User DB path */
    fprintf(fp, "\r\n");                              /* 34 Message DB path */
    fprintf(fp, "%s\r\n", info->sysop);               /* 35 Sysop */
    fprintf(fp, "%s\r\n", info->handle);              /* 36 Handle */
    fprintf(fp, "none\r\n");                          /* 37 Next event */
    fprintf(fp, "Y\r\n");                             /* 38 Error-free */
    fprintf(fp, "N\r\n");                             /* 39 Reserved */
    fprintf(fp, "Y\r\n");                             /* 40 Reserved */
    fprintf(fp, "7\r\n");                             /* 41 Text colour */
    fprintf(fp, "0\r\n");                             /* 42 Time credits */

    fprintf(fp, "\r\n");                              /* 43 Last file scan */
    fprintf(fp, "%s\r\n", call_time);                 /* 44 This call */
    fprintf(fp, "\r\n");                              /* 45 Last call */
    fprintf(fp, "32768\r\n");                         /* 46 Max daily files */
    fprintf(fp, "0\r\n");                             /* 47 Files today */
    fprintf(fp, "0\r\n");                             /* 48 KB uploaded */
    fprintf(fp, "0\r\n");                             /* 49 KB downloaded */
    fprintf(fp, "\r\n");                              /* 50 Comment */
    fprintf(fp, "0\r\n");                             /* 51 Reserved */
    fprintf(fp, "0\r\n");                             /* 52 Messages posted */

    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }

    if (fclose(fp) != 0)
        return -1;

    return 0;
}

int
write_dropfile(enum dropfile_type type,
    const char *dir,
    const struct dropfile_info *info,
    char *path,
    size_t path_size)
{
    switch (type) {
    case DROPFILE_DOOR32:
        return write_door32(dir, info, path, path_size);

    case DROPFILE_DOORSYS:
        return write_doorsys(dir, info, path, path_size);

    default:
        return -1;
    }
}
