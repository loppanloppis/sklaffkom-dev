/* ibol.h */

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

#ifndef IBOL_H
#define IBOL_H

#include <stddef.h>

struct fido_msg;

#define IBOL_AUTHOR_MAX  128
#define IBOL_SOURCE_MAX  256
#define IBOL_TEXT_MAX   4096

#define IBOL_TO_NAME     "IBBS1LINE"
#define IBOL_SUBJECT     "InterBBS Oneliner"

#define IBOL_FLAG_MYSTIC_CODES       0x0001U
#define IBOL_FLAG_ANSI_CODES         0x0002U
#define IBOL_FLAG_CONTROL_CHARS      0x0004U
#define IBOL_FLAG_TRUNCATED          0x0008U
#define IBOL_FLAG_DUPLICATE_PARTS    0x0010U
#define IBOL_FLAG_MISSING_AUTHOR     0x0020U
#define IBOL_FLAG_MISSING_SOURCE     0x0040U
#define IBOL_FLAG_UNUSUAL_SUBJECT    0x0080U

#define IBOL_PARSE_ERROR  (-1)
#define IBOL_PARSE_OK       0
#define IBOL_PARSE_EMPTY    1

struct ibol_entry {
    char author_raw[IBOL_AUTHOR_MAX];
    char source_raw[IBOL_SOURCE_MAX];
    char text_raw[IBOL_TEXT_MAX];

    char author[IBOL_AUTHOR_MAX];
    char source[IBOL_SOURCE_MAX];
    char text[IBOL_TEXT_MAX];
    char text_flat[IBOL_TEXT_MAX];

    unsigned int author_fields;
    unsigned int source_fields;
    unsigned int oneliner_fields;
    unsigned int oneliner_parts;
    unsigned int duplicate_parts;
    unsigned int flags;
};

void ibol_entry_init(struct ibol_entry *entry);

/* Return non-zero when the FTN To: field identifies an IBOL message. */
int ibol_is_message(const struct fido_msg *msg);

/*
 * Parse an IBOL body.  The entry receives both raw and sanitized fields.
 * Return IBOL_PARSE_OK on success, IBOL_PARSE_EMPTY when the message has
 * no usable Oneliner: field, or IBOL_PARSE_ERROR for invalid arguments.
 */
int ibol_parse_body(const char *body, struct ibol_entry *entry,
    char *error, size_t errorsz);

/* Identify and parse a complete FTN message; returns IBOL_PARSE_*. */
int ibol_parse_message(const struct fido_msg *msg, struct ibol_entry *entry,
    char *error, size_t errorsz);

/*
 * Produce a provisional, terminal-safe plain-text preview.
 * ftn_date may be NULL.  width values below 20 are treated as 78.
 */
int ibol_render_plain(const struct ibol_entry *entry, const char *ftn_date,
    char *out, size_t outsz, size_t width);

/* Convert common FTN dates to YYYY-MM-DD HH:MM. */
int ibol_format_ftn_date(const char *ftn_date, char *out, size_t outsz);

#endif /* IBOL_H */
