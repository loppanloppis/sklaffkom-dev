/* misc.c */

/*
 *   SklaffKOM, a simple conference system for UNIX.
 *
 *   Copyright (C) 1993-1994  Torbj|rn B}}th, Peter Forsberg, Peter Lindberg,
 *                            Odd Petersson, Carl Sundbom
 *
 *   Program dedicated to the memory of Staffan Bergstr|m.
 *
 *   For questions about this program, mail sklaff@sklaffkom.se    
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <dirent.h>
#include <sys/wait.h>
#ifdef LINUX
#include <bsd/string.h>  /* for strlcat on Linux */
#endif
#include "sklaff.h"
#include "ext_globals.h"

/*
 * ftn_initial_quote_depth - recognize FTN-style initial quote prefixes
 * args: line to check (s)
 * ret: quote depth, or 0 if not a quote
 *
 * Examples:
 *   AB>  -> 1
 *   AB>> -> 2
 *   A>   -> 1
 *   Ni>> -> 2
 *
 * modified on 2026-06-17, PL
 */
static int
ftn_initial_quote_depth(const char *s)
{
    const unsigned char *p;
    int initials = 0;
    int depth = 0;

    if (s == NULL)
        return 0;

    p = (const unsigned char *)s;

    while (*p == ' ' || *p == '\t')
        p++;

    while (isalpha((unsigned char)*p) && initials < 3) {
        p++;
        initials++;
    }

    if (initials == 0)
        return 0;

    while (*p == '>') {
        p++;
        depth++;
    }

    if (depth == 0)
        return 0;

    /*
     * Be conservative: after AB> or AB>>, require whitespace or end-of-line.
     *
     * modified on 2026-06-17, PL
     */
    if (*p == '\0' || *p == '\n' || *p == '\r' ||
        *p == ' ' || *p == '\t')
        return depth;

    return 0;
}

/* Count quote depth: skip leading spaces, then count '>' allowing optional single
 * space after each '>' so it matches ">>", "> >", "> > >", etc.
 *
 * Also recognize FTN-style quote prefixes such as "AB> ", "A> " and
 * "Ni>> ".
 *
 * modified on 2026-06-17, PL
 */
int
quote_depth(const char *s)
{
    const unsigned char *p;
    int d = 0;

    if (s == NULL)
        return 0;

    p = (const unsigned char *)s;

    while (*p == ' ' || *p == '\t')
        p++;

    while (*p == '>') {
        d++;
        p++;
        if (*p == ' ')
            p++;   /* tolerate one space after each '>' */
    }

    if (d > 0)
        return d;

    return ftn_initial_quote_depth(s);
}
/*
 * normalize_label - normalize a header label to one trailing colon and space
 * args: raw label (raw), output buffer (norm), output buffer length (nlen)
 * ret: nothing
 */
void normalize_label(const char *raw, char *norm, size_t nlen)
{
    size_t L = raw ? strlen(raw) : 0;
    int ends_with_colon = (L > 0 && raw[L-1] == ':');
    snprintf(norm, nlen, "%s%s", raw ? raw : "", ends_with_colon ? " " : ": ");
}

/* clamp_nonneg() — return v clamped to >= 0 */
/* Used in the improved "list_confs" function */
/* added 2025-10-02, PL */
long
clamp_nonneg(long v)
{
    return (v < 0) ? 0 : v;
}

/*
 * Converts unix-time to human-time format
*/
const char *
time_string_static(time_t t)
{
    static char buf[64];
    time_string(t, buf, 0);
    return buf;
}

/*                                                                              
* has_file_area - checks if conference has files               
*/ 
int 
has_file_area(int confnum) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%d%s", FILE_DB, confnum, INDEX_FILE);
    return file_exists(path) != -1;
}

const char *
swedish_month(const char *mon)
{
    if (!strcmp(mon, "Jan")) return "januari";
    if (!strcmp(mon, "Feb")) return "februari";
    if (!strcmp(mon, "Mar")) return "mars";
    if (!strcmp(mon, "Apr")) return "april";
    if (!strcmp(mon, "May")) return "maj";
    if (!strcmp(mon, "Jun")) return "juni";
    if (!strcmp(mon, "Jul")) return "juli";
    if (!strcmp(mon, "Aug")) return "augusti";
    if (!strcmp(mon, "Sep")) return "september";
    if (!strcmp(mon, "Oct")) return "oktober";
    if (!strcmp(mon, "Nov")) return "november";
    if (!strcmp(mon, "Dec")) return "december";

    return mon;
}

/*
 * sender_is_blocked - check sender against user's blocklist
 * args: blocklist text, sender name
 * ret: blocked (1) or not blocked (0)
 *
 * Blocklist format: one sender per line. Empty lines and lines beginning
 * with '#' are ignored. Matching is exact but case-insensitive.
 *
 * modified on 2026-06-16, PL
 */
int
sender_is_blocked(const char *blocklist, const char *sender)
{
    char line[LINE_LEN];
    const char *p;
    const char *start;
    size_t len;
    char *s;

    if (blocklist == NULL || sender == NULL || *sender == '\0')
        return 0;

    p = blocklist;

    while (*p) {
        while (*p == '\r' || *p == '\n')
            p++;

        start = p;

        while (*p && *p != '\n' && *p != '\r')
            p++;

        len = (size_t)(p - start);
        if (len >= sizeof(line))
            len = sizeof(line) - 1;

        memcpy(line, start, len);
        line[len] = '\0';

        s = line;

        while (*s == ' ' || *s == '\t')
            s++;

        len = strlen(s);
        while (len > 0 &&
            (s[len - 1] == ' ' || s[len - 1] == '\t'))
            s[--len] = '\0';

        if (*s != '\0' && *s != '#') {
            if (strcasecmp(s, sender) == 0)
                return 1;
        }
    }

    return 0;
}
