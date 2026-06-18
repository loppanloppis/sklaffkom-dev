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


/* Count quote depth: skip leading spaces, then count '>' allowing optional single
 * space after each '>' so it matches ">>", "> >", "> > >", etc.
 */
int quote_depth(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p == ' ' || *p == '\t') p++;
    int d = 0;
    while (*p == '>') {
        d++;
        p++;
        if (*p == ' ') p++;   /* tolerate one space after each '>' */
    }
    return d;
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
 * trim_ascii - trim leading/trailing ASCII whitespace in-place
 * args: string to trim
 * ret: none
 *
 * modified on 2026-06-18, PL
 */
static void
trim_ascii(char *s)
{
    char *p;
    size_t len;

    if (s == NULL)
        return;

    p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;

    if (p != s)
        memmove(s, p, strlen(p) + 1);

    len = strlen(s);
    while (len > 0 &&
        (s[len - 1] == ' ' || s[len - 1] == '\t' ||
         s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[--len] = '\0';
    }
}

/*
 * strip_outer_quotes - strip one surrounding quote pair
 * args: string to modify
 * ret: none
 *
 * modified on 2026-06-18, PL
 */
static void
strip_outer_quotes(char *s)
{
    size_t len;

    if (s == NULL)
        return;

    trim_ascii(s);

    len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        s[len - 1] = '\0';
        memmove(s, s + 1, len - 1);
    }

    trim_ascii(s);
}

/*
 * extract_sender_display - extract display name from "Name <addr>"
 * args: sender string, output buffer, output size
 * ret: none
 *
 * modified on 2026-06-18, PL
 */
static void
extract_sender_display(const char *sender, char *out, size_t outsz)
{
    char *lt;

    if (out == NULL || outsz == 0)
        return;

    out[0] = '\0';

    if (sender == NULL)
        return;

    strlcpy(out, sender, outsz);

    lt = strchr(out, '<');
    if (lt != NULL)
        *lt = '\0';

    strip_outer_quotes(out);
}

/*
 * extract_sender_email - extract email from "Name <addr>"
 * args: sender string, output buffer, output size
 * ret: none
 *
 * modified on 2026-06-18, PL
 */
static void
extract_sender_email(const char *sender, char *out, size_t outsz)
{
    const char *lt;
    const char *gt;
    size_t len;

    if (out == NULL || outsz == 0)
        return;

    out[0] = '\0';

    if (sender == NULL)
        return;

    lt = strchr(sender, '<');
    if (lt == NULL)
        return;

    gt = strchr(lt + 1, '>');
    if (gt == NULL)
        return;

    len = (size_t)(gt - (lt + 1));
    if (len >= outsz)
        len = outsz - 1;

    memcpy(out, lt + 1, len);
    out[len] = '\0';

    trim_ascii(out);
}

/*
 * sender_is_blocked - check sender against user's blocklist
 * args: blocklist text, sender name/address
 * ret: blocked (1) or not blocked (0)
 *
 * Blocklist format: one sender per line. Empty lines and lines beginning
 * with '#' are ignored. Matching is exact but case-insensitive.
 *
 * For imported mail/news/FTN senders, also match:
 *
 *   Full sender:   Ubuntu User <ubuntu.user@mainsite.tk>
 *   Display name:  Ubuntu User
 *   Email address: ubuntu.user@mainsite.tk
 *
 * modified on 2026-06-18, PL
 */
int
sender_is_blocked(const char *blocklist, const char *sender)
{
	LINE line;
	LONG_LINE sender_full;
	LONG_LINE sender_display;
	LINE sender_email;
    const char *p;
    const char *start;
    size_t len;

    if (blocklist == NULL || sender == NULL || *sender == '\0')
        return 0;

    strlcpy(sender_full, sender, sizeof(sender_full));
    trim_ascii(sender_full);
    strip_outer_quotes(sender_full);

    extract_sender_display(sender_full, sender_display, sizeof(sender_display));
    extract_sender_email(sender_full, sender_email, sizeof(sender_email));

    p = blocklist;

    while (*p != '\0') {
        while (*p == '\r' || *p == '\n')
            p++;

        start = p;

        while (*p != '\0' && *p != '\n' && *p != '\r')
            p++;

        len = (size_t)(p - start);
        if (len >= sizeof(line))
            len = sizeof(line) - 1;

        memcpy(line, start, len);
        line[len] = '\0';

        trim_ascii(line);
        strip_outer_quotes(line);

        if (line[0] != '\0' && line[0] != '#') {
            if (strcasecmp(line, sender_full) == 0)
                return 1;

            if (sender_display[0] != '\0' &&
                strcasecmp(line, sender_display) == 0)
                return 1;

            if (sender_email[0] != '\0' &&
                strcasecmp(line, sender_email) == 0)
                return 1;
        }
    }

    return 0;
}
