/*
 * htmlmsgdump.c - test wrapper for SklaffKOM MIME/HTML mail rendering
 *
 * Build in the SklaffKOM tree:
 *   cc -Wall -Wextra -O2 -o htmlmsgdump htmlmsgdump.c mailbody.c
 *
 * Usage:
 *   ./htmlmsgdump [-v] [-c|--clean] [message.mbox]
 *   ./htmlmsgdump [-v] [--no-clean] [message.mbox]
 *
 * If no file is given, stdin is used.  When run from a terminal without input,
 * usage is printed instead of appearing to hang.
 */

#include "mailbody.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [-v] [-c|--clean|--no-clean] [message.mbox]\n"
            "\n"
            "Options:\n"
            "  -v, --verbose   show MIME selection/debug information on stderr\n"
            "  -c, --clean     clean tracking URL parameters and whitespace\n"
            "  --no-clean      disable cleanup; cleanup is on by default\n"
            "  -h, --help      show this help\n"
            "\n"
            "Examples:\n"
            "  %s -v mail.mbox\n"
            "  %s -v --no-clean mail.mbox\n"
            "  \n",

            prog, prog, prog);
}

static void
 die(const char *msg)
{
    perror(msg);
    exit(1);
}

static void *
xmalloc(size_t n)
{
    void *p;

    p = malloc(n ? n : 1);
    if (p == NULL)
        die("malloc");

    return p;
}

static char *
read_all(FILE *fp)
{
    char *buf;
    size_t cap, len;
    int c;

    cap = 8192;
    len = 0;
    buf = xmalloc(cap + 1);

    while ((c = fgetc(fp)) != EOF) {
        if (len + 1 >= cap) {
            char *nbuf;

            cap *= 2;
            nbuf = realloc(buf, cap + 1);
            if (nbuf == NULL)
                die("realloc");
            buf = nbuf;
        }

        buf[len++] = (char)c;
    }

    buf[len] = '\0';
    return buf;
}

int
main(int argc, char **argv)
{
    FILE *fp;
    char *msg;
    char *body;
    const char *path;
    int verbose;
    int clean;
    int i;

    path = NULL;
    verbose = 0;
    clean = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 ||
            strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-c") == 0 ||
                   strcmp(argv[i], "--clean") == 0) {
            clean = 1;
        } else if (strcmp(argv[i], "--no-clean") == 0) {
            clean = 0;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (path == NULL) {
            path = argv[i];
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (path == NULL && isatty(STDIN_FILENO)) {
        usage(argv[0]);
        return 1;
    }

    if (path != NULL) {
        fp = fopen(path, "rb");
        if (fp == NULL)
            die(path);
    } else {
        fp = stdin;
    }

    msg = read_all(fp);

    if (fp != stdin)
        fclose(fp);

    body = mailbody_render_utf8_dup(msg, clean, verbose);
    free(msg);

    if (body == NULL) {
        fprintf(stderr, "htmlmsgdump: no usable MIME body found\n");
        return 1;
    }

    fputs(body, stdout);
    free(body);

    return 0;
}
