/* ibolmsgdump.c */

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

#include "ftnmsg.h"
#include "ibol.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct scan_stats {
    unsigned long files_seen;
    unsigned long msg_parse_failed;
    unsigned long non_ibol;
    unsigned long ibol_messages;
    unsigned long valid_entries;
    unsigned long empty_entries;
    unsigned long malformed_entries;
    unsigned long multipart_entries;
    unsigned long duplicate_entries;
    unsigned long mystic_entries;
    unsigned long ansi_entries;
    unsigned long control_entries;
    unsigned long truncated_entries;
    unsigned long missing_author;
    unsigned long missing_source;
    unsigned long unusual_subject;
    size_t longest_author;
    size_t longest_source;
    size_t longest_text;
    unsigned int most_parts;
};

static void usage(FILE *fp, const char *prog);
static int is_msg_file(const char *name);
static void print_flags(unsigned int flags);
static int dump_one(const char *path, size_t width);
static int scan_dir(const char *path, int list, int verbose, size_t width);
static void update_stats(struct scan_stats *stats,
    const struct ibol_entry *entry);
static void print_scan_summary(const char *path,
    const struct scan_stats *stats);
static void print_list_line(const char *filename, const struct fido_msg *msg,
    const struct ibol_entry *entry, size_t width);
static void print_shortened(const char *s, size_t max);

static void
usage(FILE *fp, const char *prog)
{
    fprintf(fp,
        "Usage:\n"
        "  %s FILE.msg\n"
        "  %s --scan [--list] [--verbose] DIRECTORY\n"
        "\n"
        "Options:\n"
        "  --scan       scan all .MSG files in one directory\n"
        "  --list       print one sanitized line per valid IBOL entry\n"
        "  --verbose    report malformed and specially sanitized entries\n"
        "  --width N    preview/list width (default 78)\n"
        "  -h, --help   show this help\n"
        "\n"
        "Build example:\n"
        "  cc -Wall -Wextra -O2 -o ibolmsgdump \\\n"
        "     ibolmsgdump.c ibol.c ftnmsg.c\n",
        prog, prog);
}

static int
is_msg_file(const char *name)
{
    const char *dot;

    if (name == NULL)
        return 0;

    dot = strrchr(name, '.');
    return dot != NULL && strcasecmp(dot, ".msg") == 0;
}

static void
print_flags(unsigned int flags)
{
    int first;

    if (flags == 0) {
        printf("none");
        return;
    }

    first = 1;
#define PRINT_FLAG(bit, name) \
    do { \
        if (flags & (bit)) { \
            printf("%s%s", first ? "" : ", ", (name)); \
            first = 0; \
        } \
    } while (0)

    PRINT_FLAG(IBOL_FLAG_MYSTIC_CODES, "mystic-codes");
    PRINT_FLAG(IBOL_FLAG_ANSI_CODES, "ansi-codes");
    PRINT_FLAG(IBOL_FLAG_CONTROL_CHARS, "control-chars");
    PRINT_FLAG(IBOL_FLAG_TRUNCATED, "truncated");
    PRINT_FLAG(IBOL_FLAG_DUPLICATE_PARTS, "duplicate-parts");
    PRINT_FLAG(IBOL_FLAG_MISSING_AUTHOR, "missing-author");
    PRINT_FLAG(IBOL_FLAG_MISSING_SOURCE, "missing-source");
    PRINT_FLAG(IBOL_FLAG_UNUSUAL_SUBJECT, "unusual-subject");

#undef PRINT_FLAG
}

static int
dump_one(const char *path, size_t width)
{
    struct fido_msg msg;
    struct ibol_entry entry;
    char error[256];
    char preview[8192];
    int rc;

    if (read_fido_msg(path, &msg) != 0) {
        fprintf(stderr, "[ERROR] Could not parse FTN .MSG file: %s\n", path);
        return 1;
    }

    printf("IBOL message dump\n");
    printf("=================\n\n");
    printf("File:       %s\n", path);
    printf("From:       %s\n", msg.from);
    printf("To:         %s\n", msg.to);
    printf("Subject:    %s\n", msg.subject);
    printf("Date:       %s\n", msg.date);
    printf("MSGID:      %s\n", msg.msgid[0] ? msg.msgid : "(missing)");
    printf("CHRS:       %s\n", msg.chrs[0] ? msg.chrs : "(missing)");
    printf("Is IBOL:    %s\n", ibol_is_message(&msg) ? "yes" : "no");

    if (!ibol_is_message(&msg)) {
        free_fido_msg(&msg);
        return 2;
    }

    rc = ibol_parse_message(&msg, &entry, error, sizeof(error));
    if (rc == IBOL_PARSE_ERROR) {
        printf("Parse:      FAILED (%s)\n", error);
        printf("\n--- CLEAN FTN BODY ---\n%s\n",
            msg.clean_body != NULL ? msg.clean_body :
            (msg.raw_body != NULL ? msg.raw_body : ""));
        free_fido_msg(&msg);
        return 3;
    }

    if (rc == IBOL_PARSE_EMPTY)
        printf("Parse:      EMPTY (%s)\n", error);
    else
        printf("Parse:      OK\n");

    printf("Fields:     Author=%u Source=%u Oneliner=%u (%u non-empty)\n",
        entry.author_fields, entry.source_fields,
        entry.oneliner_fields, entry.oneliner_parts);
    printf("Duplicates: %u adjacent duplicate part(s)\n",
        entry.duplicate_parts);
    printf("Flags:      ");
    print_flags(entry.flags);
    printf("\n\n");

    printf("Author raw:   %s\n", entry.author_raw[0] ? entry.author_raw : "(missing)");
    printf("Author clean: %s\n", entry.author[0] ? entry.author : "(missing)");
    printf("Source raw:   %s\n", entry.source_raw[0] ? entry.source_raw : "(missing)");
    printf("Source clean: %s\n", entry.source[0] ? entry.source : "(missing)");
    printf("Text raw:\n%s\n", entry.text_raw[0] ? entry.text_raw : "(empty)");
    printf("Text clean:\n%s\n", entry.text[0] ? entry.text : "(empty)");
    printf("Text flat:    %s\n",
        entry.text_flat[0] ? entry.text_flat : "(empty)");

    if (rc == IBOL_PARSE_OK) {
        printf("\n--- PROVISIONAL SKLAFFKOM PREVIEW ---\n");
        if (ibol_render_plain(&entry, msg.date, preview, sizeof(preview),
                width) == 0)
            printf("%s", preview);
        else
            printf("[preview did not fit output buffer]\n");
    } else {
        printf("\n--- CLEAN FTN BODY ---\n%s\n",
            msg.clean_body != NULL ? msg.clean_body :
            (msg.raw_body != NULL ? msg.raw_body : ""));
    }

    free_fido_msg(&msg);
    return 0;
}

static void
update_stats(struct scan_stats *stats, const struct ibol_entry *entry)
{
    size_t n;

    stats->valid_entries++;

    if (entry->oneliner_parts > 1)
        stats->multipart_entries++;
    if (entry->duplicate_parts > 0)
        stats->duplicate_entries++;
    if (entry->flags & IBOL_FLAG_MYSTIC_CODES)
        stats->mystic_entries++;
    if (entry->flags & IBOL_FLAG_ANSI_CODES)
        stats->ansi_entries++;
    if (entry->flags & IBOL_FLAG_CONTROL_CHARS)
        stats->control_entries++;
    if (entry->flags & IBOL_FLAG_TRUNCATED)
        stats->truncated_entries++;
    if (entry->flags & IBOL_FLAG_MISSING_AUTHOR)
        stats->missing_author++;
    if (entry->flags & IBOL_FLAG_MISSING_SOURCE)
        stats->missing_source++;
    if (entry->flags & IBOL_FLAG_UNUSUAL_SUBJECT)
        stats->unusual_subject++;

    n = strlen(entry->author);
    if (n > stats->longest_author)
        stats->longest_author = n;
    n = strlen(entry->source);
    if (n > stats->longest_source)
        stats->longest_source = n;
    n = strlen(entry->text_flat);
    if (n > stats->longest_text)
        stats->longest_text = n;
    if (entry->oneliner_parts > stats->most_parts)
        stats->most_parts = entry->oneliner_parts;
}

static void
print_shortened(const char *s, size_t max)
{
    size_t len;

    if (s == NULL)
        s = "";

    len = strlen(s);
    if (len <= max) {
        fputs(s, stdout);
        return;
    }

    if (max <= 3) {
        fwrite(s, 1, max, stdout);
        return;
    }

    fwrite(s, 1, max - 3, stdout);
    fputs("...", stdout);
}

static void
print_list_line(const char *filename, const struct fido_msg *msg,
    const struct ibol_entry *entry, size_t width)
{
    char datebuf[64];
    size_t fixed;
    size_t textmax;
    const char *author;

    if (ibol_format_ftn_date(msg->date, datebuf, sizeof(datebuf)) != 0)
        snprintf(datebuf, sizeof(datebuf), "%-16.16s", msg->date);

    author = entry->author[0] ? entry->author : msg->from;
    fixed = 16 + 1 + 8 + 1 + 18 + 3;
    textmax = width > fixed ? width - fixed : 24;

    printf("%-16.16s %-8.8s %-18.18s | ", datebuf, filename, author);
    print_shortened(entry->text_flat, textmax);
    printf("\n");
}

static int
scan_dir(const char *path, int list, int verbose, size_t width)
{
    DIR *dir;
    struct dirent *de;
    struct scan_stats stats;
    char fullpath[PATH_MAX];

    memset(&stats, 0, sizeof(stats));

    dir = opendir(path);
    if (dir == NULL) {
        fprintf(stderr, "[ERROR] Could not open directory '%s': %s\n",
            path, strerror(errno));
        return 1;
    }

    if (list)
        printf("Date             File     Author             | Oneliner\n"
               "---------------- -------- ------------------ | --------\n");

    while ((de = readdir(dir)) != NULL) {
        struct fido_msg msg;
        struct ibol_entry entry;
        char error[256];
        int rc;

        if (!is_msg_file(de->d_name))
            continue;

        stats.files_seen++;

        if (snprintf(fullpath, sizeof(fullpath), "%s/%s",
                path, de->d_name) >= (int)sizeof(fullpath)) {
            fprintf(stderr, "[ERROR] Path too long: %s/%s\n", path, de->d_name);
            stats.msg_parse_failed++;
            continue;
        }

        if (read_fido_msg(fullpath, &msg) != 0) {
            stats.msg_parse_failed++;
            if (verbose)
                printf("[FTN PARSE FAILED] %s\n", de->d_name);
            continue;
        }

        if (!ibol_is_message(&msg)) {
            stats.non_ibol++;
            free_fido_msg(&msg);
            continue;
        }

        stats.ibol_messages++;
        rc = ibol_parse_message(&msg, &entry, error, sizeof(error));
        if (rc == IBOL_PARSE_EMPTY) {
            stats.empty_entries++;
            if (verbose)
                printf("[EMPTY] %-12s %s\n", de->d_name, error);
            free_fido_msg(&msg);
            continue;
        }
        if (rc == IBOL_PARSE_ERROR) {
            stats.malformed_entries++;
            if (verbose)
                printf("[MALFORMED] %-12s %s\n", de->d_name, error);
            free_fido_msg(&msg);
            continue;
        }

        update_stats(&stats, &entry);

        if (list)
            print_list_line(de->d_name, &msg, &entry, width);

        if (verbose && entry.flags != 0) {
            printf("[FLAGS] %-12s ", de->d_name);
            print_flags(entry.flags);
            printf("\n");
        }

        free_fido_msg(&msg);
    }

    closedir(dir);
    print_scan_summary(path, &stats);

    return stats.msg_parse_failed != 0 ? 1 : 0;
}

static void
print_scan_summary(const char *path, const struct scan_stats *stats)
{
    printf("\nIBOL scan summary\n");
    printf("=================\n");
    printf("Directory:                  %s\n", path);
    printf(".MSG files seen:            %lu\n", stats->files_seen);
    printf("FTN parse failures:         %lu\n", stats->msg_parse_failed);
    printf("Non-IBOL messages:          %lu\n", stats->non_ibol);
    printf("IBOL messages:              %lu\n", stats->ibol_messages);
    printf("Valid IBOL entries:         %lu\n", stats->valid_entries);
    printf("Empty IBOL entries:         %lu\n", stats->empty_entries);
    printf("Malformed IBOL entries:     %lu\n", stats->malformed_entries);
    printf("Multiple Oneliner parts:    %lu\n", stats->multipart_entries);
    printf("Adjacent duplicate parts:   %lu\n", stats->duplicate_entries);
    printf("Mystic codes removed:       %lu\n", stats->mystic_entries);
    printf("ANSI sequences removed:     %lu\n", stats->ansi_entries);
    printf("Control characters removed: %lu\n", stats->control_entries);
    printf("Truncated fields:           %lu\n", stats->truncated_entries);
    printf("Missing Author:             %lu\n", stats->missing_author);
    printf("Missing Source:             %lu\n", stats->missing_source);
    printf("Unusual Subject:            %lu\n", stats->unusual_subject);
    printf("Longest clean Author:       %lu byte(s)\n",
        (unsigned long)stats->longest_author);
    printf("Longest clean Source:       %lu byte(s)\n",
        (unsigned long)stats->longest_source);
    printf("Longest clean Oneliner:     %lu byte(s)\n",
        (unsigned long)stats->longest_text);
    printf("Most Oneliner parts:        %u\n", stats->most_parts);
}

int
main(int argc, char **argv)
{
    int scan;
    int list;
    int verbose;
    size_t width;
    const char *path;
    int i;

    scan = 0;
    list = 0;
    verbose = 0;
    width = 78;
    path = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scan") == 0) {
            scan = 1;
        } else if (strcmp(argv[i], "--list") == 0) {
            list = 1;
        } else if (strcmp(argv[i], "--verbose") == 0 ||
            strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "--width") == 0) {
            char *end;
            unsigned long n;

            if (++i >= argc) {
                fprintf(stderr, "[ERROR] --width requires a number\n");
                return 2;
            }
            errno = 0;
            n = strtoul(argv[i], &end, 10);
            if (errno != 0 || *end != '\0' || n < 20 || n > 500) {
                fprintf(stderr, "[ERROR] Invalid width: %s\n", argv[i]);
                return 2;
            }
            width = (size_t)n;
        } else if (strcmp(argv[i], "--help") == 0 ||
            strcmp(argv[i], "-h") == 0) {
            usage(stdout, argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "[ERROR] Unknown option: %s\n", argv[i]);
            usage(stderr, argv[0]);
            return 2;
        } else if (path == NULL) {
            path = argv[i];
        } else {
            fprintf(stderr, "[ERROR] Too many paths\n");
            usage(stderr, argv[0]);
            return 2;
        }
    }

    if (path == NULL) {
        usage(stderr, argv[0]);
        return 2;
    }

    if (scan)
        return scan_dir(path, list, verbose, width);

    if (list || verbose) {
        fprintf(stderr, "[ERROR] --list and --verbose require --scan\n");
        return 2;
    }

    return dump_one(path, width);
}
