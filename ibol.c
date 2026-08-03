/* ibol.c */

/*
 *   SklaffKOM, a simple conference system for UNIX.
 *
 *   Copyright (C) 1993-1994  Torbjörn Bååth, Peter Forsberg, Peter Lindberg,
 *                            Odd Petersson, Carl Sundbom
 *   Copyright (C) 2026       Peter London
 *
 *   Program dedicated to the memory of Staffan Bergström.
 *
 *   For questions about this program, mail sklaff@sklaffkom.se
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "ibol.h"
#include "ftnmsg.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void set_error(char *error, size_t errorsz, const char *fmt, ...);
static int ibol_recipient_matches(const char *to);
static int field_value(const char *line, size_t linelen, const char *name,
    const char **value, size_t *valuelen);
static int field_value_layout(const char *line, size_t linelen,
    const char *name, const char **value, size_t *valuelen);
static int copy_segment(char *dst, size_t dstsz, const char *src, size_t srclen);
static int append_segment(char *dst, size_t dstsz, const char *src,
    size_t srclen, char separator);
static void sanitize_field(const char *src, char *dst, size_t dstsz,
    unsigned int *flags);
static void sanitize_text_layout(const char *src, char *dst, size_t dstsz,
    unsigned int *flags);
static void flatten_text(const char *src, char *dst, size_t dstsz);
static int text_has_content(const char *text);
static void utf8_safe_end(char *s);
static int mystic_code_length(const unsigned char *p);
static size_t ansi_code_length(const unsigned char *p);
static int subject_matches(const char *subject);
static int append_output(char *out, size_t outsz, size_t *used,
    const char *fmt, ...);
static int append_wrapped(char *out, size_t outsz, size_t *used,
    const char *text, size_t width);

void
ibol_entry_init(struct ibol_entry *entry)
{
    if (entry != NULL)
        memset(entry, 0, sizeof(*entry));
}

static void
set_error(char *error, size_t errorsz, const char *fmt, ...)
{
    va_list ap;

    if (error == NULL || errorsz == 0)
        return;

    va_start(ap, fmt);
    vsnprintf(error, errorsz, fmt, ap);
    va_end(ap);
}

static int
ibol_recipient_matches(const char *to)
{
    const char *p;
    size_t n;

    if (to == NULL)
        return 0;

    n = strlen(IBOL_TO_NAME);
    for (p = to; *p != '\0'; p++) {
        unsigned char before;
        unsigned char after;

        if (strlen(p) < n)
            break;
        if (strncasecmp(p, IBOL_TO_NAME, n) != 0)
            continue;

        before = (p == to) ? 0 : (unsigned char)p[-1];
        after = (unsigned char)p[n];

        if ((before == 0 || !isalnum(before)) &&
            (after == 0 || !isalnum(after)))
            return 1;
    }

    return 0;
}

int
ibol_is_message(const struct fido_msg *msg)
{
    if (msg == NULL)
        return 0;

    return ibol_recipient_matches(msg->to);
}

static int
field_value(const char *line, size_t linelen, const char *name,
    const char **value, size_t *valuelen)
{
    const char *p;
    const char *end;
    size_t namelen;

    if (line == NULL || name == NULL || value == NULL || valuelen == NULL)
        return 0;

    p = line;
    end = line + linelen;

    while (p < end && (*p == ' ' || *p == '\t'))
        p++;

    namelen = strlen(name);
    if ((size_t)(end - p) < namelen + 1)
        return 0;
    if (strncasecmp(p, name, namelen) != 0 || p[namelen] != ':')
        return 0;

    p += namelen + 1;
    while (p < end && (*p == ' ' || *p == '\t'))
        p++;
    while (end > p && (end[-1] == ' ' || end[-1] == '\t'))
        end--;

    *value = p;
    *valuelen = (size_t)(end - p);
    return 1;
}

static int
field_value_layout(const char *line, size_t linelen, const char *name,
    const char **value, size_t *valuelen)
{
    const char *p;
    const char *end;
    size_t namelen;

    if (line == NULL || name == NULL || value == NULL || valuelen == NULL)
        return 0;

    p = line;
    end = line + linelen;

    while (p < end && (*p == ' ' || *p == '\t'))
        p++;

    namelen = strlen(name);
    if ((size_t)(end - p) < namelen + 1)
        return 0;
    if (strncasecmp(p, name, namelen) != 0 || p[namelen] != ':')
        return 0;

    p += namelen + 1;

    /* Remove one conventional separator, but preserve further indentation. */
    if (p < end && (*p == ' ' || *p == '\t'))
        p++;

    *value = p;
    *valuelen = (size_t)(end - p);
    return 1;
}

static int
copy_segment(char *dst, size_t dstsz, const char *src, size_t srclen)
{
    size_t n;
    int truncated;

    if (dst == NULL || dstsz == 0)
        return srclen != 0;

    n = srclen;
    truncated = 0;
    if (n >= dstsz) {
        n = dstsz - 1;
        truncated = 1;
    }

    if (n > 0 && src != NULL)
        memcpy(dst, src, n);
    dst[n] = '\0';
    utf8_safe_end(dst);

    return truncated;
}

static int
append_segment(char *dst, size_t dstsz, const char *src, size_t srclen,
    char separator)
{
    size_t used;
    size_t need;
    size_t room;
    size_t n;
    int truncated;

    if (dst == NULL || dstsz == 0)
        return srclen != 0;

    used = strlen(dst);
    truncated = 0;

    if (separator != '\0' && used > 0) {
        if (used + 1 < dstsz) {
            dst[used++] = separator;
            dst[used] = '\0';
        } else {
            return 1;
        }
    }

    room = dstsz - used - 1;
    need = srclen;
    n = need;
    if (n > room) {
        n = room;
        truncated = 1;
    }

    if (n > 0 && src != NULL)
        memcpy(dst + used, src, n);
    dst[used + n] = '\0';
    utf8_safe_end(dst);

    return truncated;
}

static void
utf8_safe_end(char *s)
{
    size_t len;
    size_t start;
    unsigned char lead;
    size_t expected;
    size_t actual;

    if (s == NULL)
        return;

    len = strlen(s);
    if (len == 0)
        return;

    start = len - 1;
    while (start > 0 && ((unsigned char)s[start] & 0xc0U) == 0x80U)
        start--;

    lead = (unsigned char)s[start];
    if (lead < 0x80U)
        expected = 1;
    else if ((lead & 0xe0U) == 0xc0U)
        expected = 2;
    else if ((lead & 0xf0U) == 0xe0U)
        expected = 3;
    else if ((lead & 0xf8U) == 0xf0U)
        expected = 4;
    else {
        s[start] = '\0';
        return;
    }

    actual = len - start;
    if (actual < expected)
        s[start] = '\0';
}

static int
mystic_code_length(const unsigned char *p)
{
    static const char *known[] = {
        "CR", "CL", "PA", "DE", "PN", "PI", "PO", "BS", "LF", NULL
    };
    int i;

    if (p == NULL || p[0] != '|' || p[1] == '\0' || p[2] == '\0')
        return 0;

    if (isdigit(p[1]) && isdigit(p[2]))
        return 3;

    for (i = 0; known[i] != NULL; i++) {
        if (toupper(p[1]) == known[i][0] &&
            toupper(p[2]) == known[i][1])
            return 3;
    }

    return 0;
}

static size_t
ansi_code_length(const unsigned char *p)
{
    size_t i;

    if (p == NULL)
        return 0;

    if (p[0] != 0x1bU)
        return 0;

    if (p[1] == '[') {
        for (i = 2; p[i] != '\0'; i++) {
            if (p[i] >= 0x40U && p[i] <= 0x7eU)
                return i + 1;
        }
        return i;
    }

    if (p[1] == ']') {
        for (i = 2; p[i] != '\0'; i++) {
            if (p[i] == 0x07U)
                return i + 1;
            if (p[i] == 0x1bU && p[i + 1] == '\\')
                return i + 2;
        }
        return i;
    }

    if (p[1] != '\0')
        return 2;

    return 1;
}

static void
sanitize_field(const char *src, char *dst, size_t dstsz,
    unsigned int *flags)
{
    const unsigned char *p;
    size_t used;
    int pending_space;

    if (dst == NULL || dstsz == 0)
        return;

    dst[0] = '\0';
    if (src == NULL)
        return;

    p = (const unsigned char *)src;
    used = 0;
    pending_space = 0;

    while (*p != '\0') {
        int mlen;
        size_t alen;
        unsigned char ch;

        mlen = mystic_code_length(p);
        if (mlen > 0) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_MYSTIC_CODES;
            p += mlen;
            continue;
        }

        alen = ansi_code_length(p);
        if (alen > 0) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_ANSI_CODES;
            p += alen;
            continue;
        }

        ch = *p++;
        if (ch < 0x20U || ch == 0x7fU) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_CONTROL_CHARS;
            pending_space = (used > 0);
            continue;
        }

        if (ch == ' ' || ch == '\t') {
            pending_space = (used > 0);
            continue;
        }

        if (pending_space) {
            if (used + 1 >= dstsz) {
                if (flags != NULL)
                    *flags |= IBOL_FLAG_TRUNCATED;
                break;
            }
            dst[used++] = ' ';
            pending_space = 0;
        }

        if (used + 1 >= dstsz) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_TRUNCATED;
            break;
        }

        dst[used++] = (char)ch;
    }

    dst[used] = '\0';
    utf8_safe_end(dst);
}

static void
sanitize_text_layout(const char *src, char *dst, size_t dstsz,
    unsigned int *flags)
{
    const unsigned char *p;
    size_t used;
    size_t col;

    if (dst == NULL || dstsz == 0)
        return;

    dst[0] = '\0';
    if (src == NULL)
        return;

    p = (const unsigned char *)src;
    used = 0;
    col = 0;

    while (*p != '\0') {
        int mlen;
        size_t alen;
        unsigned char ch;

        mlen = mystic_code_length(p);
        if (mlen > 0) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_MYSTIC_CODES;
            p += mlen;
            continue;
        }

        alen = ansi_code_length(p);
        if (alen > 0) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_ANSI_CODES;
            p += alen;
            continue;
        }

        ch = *p++;
        if (ch == '\n') {
            if (used + 1 >= dstsz) {
                if (flags != NULL)
                    *flags |= IBOL_FLAG_TRUNCATED;
                break;
            }
            dst[used++] = '\n';
            col = 0;
            continue;
        }

        if (ch == '\t') {
            size_t spaces;

            if (flags != NULL)
                *flags |= IBOL_FLAG_CONTROL_CHARS;
            spaces = 8U - (col % 8U);
            while (spaces-- > 0) {
                if (used + 1 >= dstsz) {
                    if (flags != NULL)
                        *flags |= IBOL_FLAG_TRUNCATED;
                    goto done;
                }
                dst[used++] = ' ';
                col++;
            }
            continue;
        }

        if (ch < 0x20U || ch == 0x7fU) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_CONTROL_CHARS;
            continue;
        }

        if (used + 1 >= dstsz) {
            if (flags != NULL)
                *flags |= IBOL_FLAG_TRUNCATED;
            break;
        }

        dst[used++] = (char)ch;
        col++;
    }

done:
    while (used > 0 && (dst[used - 1] == '\n' || dst[used - 1] == ' ' ||
        dst[used - 1] == '\t'))
        used--;

    dst[used] = '\0';
    utf8_safe_end(dst);
}

static void
flatten_text(const char *src, char *dst, size_t dstsz)
{
    const unsigned char *p;
    size_t used;
    int pending_space;

    if (dst == NULL || dstsz == 0)
        return;

    dst[0] = '\0';
    if (src == NULL)
        return;

    p = (const unsigned char *)src;
    used = 0;
    pending_space = 0;

    while (*p != '\0') {
        unsigned char ch;

        ch = *p++;
        if (isspace(ch)) {
            pending_space = (used > 0);
            continue;
        }

        if (pending_space) {
            if (used + 1 >= dstsz)
                break;
            dst[used++] = ' ';
            pending_space = 0;
        }

        if (used + 1 >= dstsz)
            break;
        dst[used++] = (char)ch;
    }

    dst[used] = '\0';
    utf8_safe_end(dst);
}

static int
text_has_content(const char *text)
{
    const unsigned char *p;

    if (text == NULL)
        return 0;

    for (p = (const unsigned char *)text; *p != '\0'; p++) {
        if (!isspace(*p))
            return 1;
    }

    return 0;
}

int
ibol_parse_body(const char *body, struct ibol_entry *entry,
    char *error, size_t errorsz)
{
    const char *p;
    char previous[IBOL_TEXT_MAX];
    size_t previous_len;

    if (entry == NULL) {
        set_error(error, errorsz, "entry is NULL");
        return IBOL_PARSE_ERROR;
    }

    ibol_entry_init(entry);
    previous[0] = '\0';
    previous_len = 0;

    if (body == NULL) {
        set_error(error, errorsz, "message body is empty");
        return IBOL_PARSE_EMPTY;
    }

    p = body;
    while (*p != '\0') {
        const char *line;
        const char *value;
        size_t linelen;
        size_t valuelen;
        int truncated;

        line = p;
        while (*p != '\0' && *p != '\r' && *p != '\n')
            p++;
        linelen = (size_t)(p - line);

        if (*p == '\r' || *p == '\n') {
            char first = *p++;
            if ((*p == '\r' || *p == '\n') && *p != first)
                p++;
        }

        if (field_value(line, linelen, "Author", &value, &valuelen)) {
            entry->author_fields++;
            truncated = copy_segment(entry->author_raw,
                sizeof(entry->author_raw), value, valuelen);
            if (truncated)
                entry->flags |= IBOL_FLAG_TRUNCATED;
            continue;
        }

        if (field_value(line, linelen, "Source", &value, &valuelen)) {
            entry->source_fields++;
            truncated = copy_segment(entry->source_raw,
                sizeof(entry->source_raw), value, valuelen);
            if (truncated)
                entry->flags |= IBOL_FLAG_TRUNCATED;
            continue;
        }

        if (field_value_layout(line, linelen, "Oneliner", &value,
                &valuelen)) {
            const char *q;
            int has_nonspace;

            entry->oneliner_fields++;
            has_nonspace = 0;
            for (q = value; q < value + valuelen; q++) {
                if (*q != ' ' && *q != '\t') {
                    has_nonspace = 1;
                    break;
                }
            }
            if (!has_nonspace)
                continue;

            if (previous_len == valuelen &&
                memcmp(previous, value, valuelen) == 0) {
                entry->duplicate_parts++;
                entry->flags |= IBOL_FLAG_DUPLICATE_PARTS;
            }

            if (copy_segment(previous, sizeof(previous), value, valuelen))
                entry->flags |= IBOL_FLAG_TRUNCATED;
            previous_len = strlen(previous);

            truncated = append_segment(entry->text_raw,
                sizeof(entry->text_raw), value, valuelen,
                entry->oneliner_parts != 0 ? '\n' : '\0');
            if (truncated)
                entry->flags |= IBOL_FLAG_TRUNCATED;

            entry->oneliner_parts++;
        }
    }

    sanitize_field(entry->author_raw, entry->author,
        sizeof(entry->author), &entry->flags);
    sanitize_field(entry->source_raw, entry->source,
        sizeof(entry->source), &entry->flags);
    sanitize_text_layout(entry->text_raw, entry->text,
        sizeof(entry->text), &entry->flags);
    flatten_text(entry->text, entry->text_flat, sizeof(entry->text_flat));

    if (entry->author[0] == '\0')
        entry->flags |= IBOL_FLAG_MISSING_AUTHOR;
    if (entry->source[0] == '\0')
        entry->flags |= IBOL_FLAG_MISSING_SOURCE;

    if (entry->oneliner_parts == 0 || !text_has_content(entry->text)) {
        set_error(error, errorsz, "no usable Oneliner: field found");
        return IBOL_PARSE_EMPTY;
    }

    if (error != NULL && errorsz > 0)
        error[0] = '\0';

    return IBOL_PARSE_OK;
}

static int
subject_matches(const char *subject)
{
    const char *start;
    const char *end;
    const char *open;
    char normalized[128];
    size_t used;
    const char *p;

    if (subject == NULL)
        return 0;

    start = subject;
    while (*start != '\0' && isspace((unsigned char)*start))
        start++;

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1]))
        end--;

    /* Accept multipart suffixes such as "(1/2)". */
    if (end > start && end[-1] == ')') {
        open = end - 1;
        while (open > start && *open != '(')
            open--;
        if (*open == '(') {
            const char *q;
            int slash;
            int valid;
            int digits_before;
            int digits_after;

            slash = 0;
            valid = (open + 1 < end - 1);
            digits_before = 0;
            digits_after = 0;
            for (q = open + 1; q < end - 1; q++) {
                if (*q == '/') {
                    if (slash != 0) {
                        valid = 0;
                        break;
                    }
                    slash = 1;
                } else if (!isdigit((unsigned char)*q)) {
                    valid = 0;
                    break;
                } else if (slash == 0) {
                    digits_before = 1;
                } else {
                    digits_after = 1;
                }
            }
            if (valid && slash != 0 && digits_before && digits_after) {
                end = open;
                while (end > start && isspace((unsigned char)end[-1]))
                    end--;
            }
        }
    }

    used = 0;
    for (p = start; p < end; p++) {
        unsigned char ch;

        ch = (unsigned char)*p;
        if (!isalnum(ch))
            continue;
        if (used + 1 >= sizeof(normalized))
            return 0;
        normalized[used++] = (char)tolower(ch);
    }
    normalized[used] = '\0';

    return strcmp(normalized, "interbbsoneliner") == 0;
}

int
ibol_parse_message(const struct fido_msg *msg, struct ibol_entry *entry,
    char *error, size_t errorsz)
{
    const char *body;
    int rc;

    if (msg == NULL || entry == NULL) {
        set_error(error, errorsz, "message or entry is NULL");
        return IBOL_PARSE_ERROR;
    }

    if (!ibol_is_message(msg)) {
        set_error(error, errorsz, "To: field is not addressed to %s",
            IBOL_TO_NAME);
        return IBOL_PARSE_ERROR;
    }

    body = msg->clean_body;
    if (body == NULL)
        body = msg->raw_body;

    rc = ibol_parse_body(body, entry, error, errorsz);

    if (!subject_matches(msg->subject))
        entry->flags |= IBOL_FLAG_UNUSUAL_SUBJECT;

    return rc;
}

int
ibol_format_ftn_date(const char *ftn_date, char *out, size_t outsz)
{
    static const char *months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    int day;
    int year;
    int hour;
    int min;
    int sec;
    int month;
    int i;
    char mon[8];

    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';

    if (ftn_date == NULL)
        return -1;

    day = year = hour = min = sec = 0;
    mon[0] = '\0';

    if (sscanf(ftn_date, " %d %7s %d %d:%d:%d",
            &day, mon, &year, &hour, &min, &sec) != 6)
        return -1;

    month = -1;
    for (i = 0; i < 12; i++) {
        if (strcasecmp(mon, months[i]) == 0) {
            month = i + 1;
            break;
        }
    }

    if (month < 1 || day < 1 || day > 31 || hour < 0 || hour > 23 ||
        min < 0 || min > 59 || sec < 0 || sec > 60)
        return -1;

    if (year < 70)
        year += 2000;
    else if (year < 100)
        year += 1900;

    if (snprintf(out, outsz, "%04d-%02d-%02d %02d:%02d",
            year, month, day, hour, min) >= (int)outsz) {
        out[0] = '\0';
        return -1;
    }

    return 0;
}

static int
append_output(char *out, size_t outsz, size_t *used, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (out == NULL || used == NULL || *used >= outsz)
        return -1;

    va_start(ap, fmt);
    n = vsnprintf(out + *used, outsz - *used, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= outsz - *used) {
        out[outsz - 1] = '\0';
        return -1;
    }

    *used += (size_t)n;
    return 0;
}

static int
append_wrapped(char *out, size_t outsz, size_t *used,
    const char *text, size_t width)
{
    const char *p;

    if (text == NULL)
        return 0;

    p = text;
    for (;;) {
        const char *line;
        size_t linelen;

        line = p;
        while (*p != '\0' && *p != '\n')
            p++;
        linelen = (size_t)(p - line);

        while (linelen > width) {
            size_t cut;
            size_t i;

            cut = width;
            for (i = width; i > 0; i--) {
                if (line[i] == ' ') {
                    cut = i;
                    break;
                }
            }
            if (cut == 0)
                cut = width;

            if (append_output(out, outsz, used, "%.*s\n",
                    (int)cut, line) != 0)
                return -1;

            line += cut;
            linelen -= cut;
            if (linelen > 0 && *line == ' ') {
                line++;
                linelen--;
            }
        }

        if (append_output(out, outsz, used, "%.*s\n",
                (int)linelen, line) != 0)
            return -1;

        if (*p == '\0')
            break;
        p++;
    }

    return 0;
}

int
ibol_render_plain(const struct ibol_entry *entry, const char *ftn_date,
    char *out, size_t outsz, size_t width)
{
    char datebuf[64];
    const char *author;
    const char *source;
    size_t used;

    if (entry == NULL || out == NULL || outsz == 0)
        return -1;

    out[0] = '\0';
    used = 0;

    if (width < 20)
        width = 78;

    author = entry->author[0] ? entry->author : "(unknown)";
    source = entry->source[0] ? entry->source : "(unknown BBS)";

    if (ibol_format_ftn_date(ftn_date, datebuf, sizeof(datebuf)) != 0) {
        if (ftn_date != NULL && *ftn_date != '\0')
            snprintf(datebuf, sizeof(datebuf), "%s", ftn_date);
        else
            snprintf(datebuf, sizeof(datebuf), "(unknown date)");
    }

    if (append_output(out, outsz, &used, "%s - %s @ %s\n",
            datebuf, author, source) != 0)
        return -1;

    if (append_wrapped(out, outsz, &used, entry->text, width) != 0)
        return -1;

    return 0;
}
