#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "sklaff.h"

static char *
mail_body_fallback_dup(const char *msg)
{
    const char *body;

    if (msg == NULL)
        return NULL;

    body = strstr(msg, "\r\n\r\n");
    if (body)
        return strdup(body + 4);

    body = strstr(msg, "\n\n");
    if (body)
        return strdup(body + 2);

    return strdup(msg);
}

char *
mail_extract_text_plain_dup(const char *msg)
{
    /*
     * Första enkla versionen:
     * - hitta boundary=
     * - leta text/plain-del
     * - returnera bodyn före nästa boundary
     * - fallback: body after headers
     */
    const char *p, *body, *next_boundary;
    char boundary[256];
    const char *bstart, *bend;
    char marker[300];
    size_t len;

    /*
     * Find boundary="..."
     */
    bstart = strcasestr(msg, "boundary=");
    if (!bstart)
		return mail_body_fallback_dup(msg);

    bstart += 9;

    if (*bstart == '"') {
        bstart++;
        bend = strchr(bstart, '"');
    } else {
        bend = bstart;
        while (*bend && *bend != '\r' && *bend != '\n' && *bend != ';')
            bend++;
    }

    if (!bend || bend <= bstart)
		return mail_body_fallback_dup(msg);

    len = (size_t)(bend - bstart);
    if (len >= sizeof(boundary))
        len = sizeof(boundary) - 1;

    memcpy(boundary, bstart, len);
    boundary[len] = '\0';

    snprintf(marker, sizeof(marker), "--%s", boundary);

    p = msg;
    while ((p = strstr(p, marker)) != NULL) {
        const char *part_headers;
        const char *part_body;

        p += strlen(marker);

        /*
         * End marker --boundary--
         */
        if (p[0] == '-' && p[1] == '-')
            break;

        part_headers = p;

        part_body = strstr(part_headers, "\n\n");
        if (!part_body)
            part_body = strstr(part_headers, "\r\n\r\n");

        if (!part_body)
            break;

        if (strstr(part_headers, "text/plain") ||
            strstr(part_headers, "Text/Plain") ||
            strstr(part_headers, "TEXT/PLAIN")) {
            if (part_body[0] == '\r' && part_body[1] == '\n' &&
                part_body[2] == '\r' && part_body[3] == '\n')
                body = part_body + 4;
            else
                body = part_body + 2;

            next_boundary = strstr(body, marker);
			if (!next_boundary)
    			return strdup(body);

			len = (size_t)(next_boundary - body);
			{
    			char *out = malloc(len + 1);
    			if (!out)
        			return NULL;
    			memcpy(out, body, len);
    			out[len] = '\0';
    			return out;
			}
        }
    }

    /*
     * Fallback: old behavior-ish.
     */
    return mail_body_fallback_dup(msg);
}

static int
hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

char *
mail_qp_decode_dup(const char *src)
{
    const unsigned char *s;
    char *out, *d;
    int h1, h2;

    if (!src)
        return NULL;

    out = malloc(strlen(src) + 1);
    if (!out)
        return NULL;

    s = (const unsigned char *)src;
    d = out;

    while (*s) {
        if (*s == '=') {
            /*
             * Soft line break:
             * =\n
             * =\r\n
             */
            if (s[1] == '\r' && s[2] == '\n') {
                s += 3;
                continue;
            }
            if (s[1] == '\n') {
                s += 2;
                continue;
            }

            h1 = hexval(s[1]);
            h2 = hexval(s[2]);
            if (h1 >= 0 && h2 >= 0) {
                *d++ = (char)((h1 << 4) | h2);
                s += 3;
                continue;
            }
        }

        *d++ = (char)*s++;
    }

    *d = '\0';
    return out;
}

int
mail_has_quoted_printable(const char *msg)
{
    if (msg == NULL)
        return 0;

    return strcasestr(msg, "Content-Transfer-Encoding: quoted-printable") != NULL;
}
static int
b64val(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;

    return -1;
}

char *
mail_base64_decode_dup(const char *src)
{
    const unsigned char *s;
    unsigned char *out, *d;
    int vals[4];
    int n, v;
    size_t len;

    if (src == NULL)
        return NULL;

    len = strlen(src);
    out = malloc(len + 1);
    if (out == NULL)
        return NULL;

    s = (const unsigned char *)src;
    d = out;
    n = 0;

    while (*s) {
        if (*s == '=') {
            vals[n++] = -2;      /* padding */
        } else {
            v = b64val(*s);
            if (v < 0) {
                s++;
                continue;        /* skip CR/LF/spaces/etc */
            }
            vals[n++] = v;
        }

        if (n == 4) {
            if (vals[0] >= 0 && vals[1] >= 0) {
                *d++ = (unsigned char)((vals[0] << 2) | (vals[1] >> 4));
            }

            if (vals[2] >= 0) {
                *d++ = (unsigned char)(((vals[1] & 0x0f) << 4) | (vals[2] >> 2));
            }

            if (vals[3] >= 0) {
                *d++ = (unsigned char)(((vals[2] & 0x03) << 6) | vals[3]);
            }

            n = 0;
        }

        s++;
    }

    *d = '\0';
    return (char *)out;
}

int
mail_has_base64(const char *msg)
{
    if (msg == NULL)
        return 0;

    return strcasestr(msg, "Content-Transfer-Encoding: base64") != NULL;
}

struct mail_sbuf {
    char *data;
    size_t len;
    size_t cap;
};

static int
mail_sbuf_grow(struct mail_sbuf *b, size_t extra)
{
    char *nbuf;

    if (b->len + extra + 1 <= b->cap)
        return 0;

    while (b->len + extra + 1 > b->cap)
        b->cap *= 2;

    nbuf = realloc(b->data, b->cap);
    if (nbuf == NULL)
        return -1;

    b->data = nbuf;
    return 0;
}

static int
mail_sbuf_init(struct mail_sbuf *b)
{
    b->cap = 128;
    b->len = 0;
    b->data = malloc(b->cap);
    if (b->data == NULL)
        return -1;
    b->data[0] = '\0';
    return 0;
}

static int
mail_sbuf_putc(struct mail_sbuf *b, int c)
{
    if (mail_sbuf_grow(b, 1) == -1)
        return -1;

    b->data[b->len++] = (char)c;
    b->data[b->len] = '\0';
    return 0;
}

static int
mail_sbuf_putn(struct mail_sbuf *b, const char *s, size_t n)
{
    if (n == 0)
        return 0;

    if (mail_sbuf_grow(b, n) == -1)
        return -1;

    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

static char *
mail_trim_dup(const char *s, size_t len)
{
    const char *start;
    const char *end;
    char *out;

    if (s == NULL)
        return NULL;

    start = s;
    end = s + len;

    while (start < end && isspace((unsigned char)*start))
        start++;

    while (end > start && isspace((unsigned char)end[-1]))
        end--;

    out = malloc((size_t)(end - start) + 1);
    if (out == NULL)
        return NULL;

    memcpy(out, start, (size_t)(end - start));
    out[end - start] = '\0';
    return out;
}

char *
mail_header_value_dup(const char *msg, const char *name)
{
    const char *headers_end;
    const char *p;
    size_t namelen;

    if (msg == NULL || name == NULL)
        return NULL;

    headers_end = strstr(msg, "\r\n\r\n");
    if (headers_end == NULL)
        headers_end = strstr(msg, "\n\n");
    if (headers_end == NULL)
        headers_end = msg + strlen(msg);

    namelen = strlen(name);
    p = msg;

    while (p < headers_end && *p != '\0') {
        const char *line_end;
        size_t line_len;

        line_end = memchr(p, '\n', (size_t)(headers_end - p));
        if (line_end == NULL)
            line_end = headers_end;

        line_len = (size_t)(line_end - p);
        if (line_len > 0 && p[line_len - 1] == '\r')
            line_len--;

        if (line_len == 0)
            break;

        if (line_len > namelen && strncasecmp(p, name, namelen) == 0 &&
            p[namelen] == ':') {
            struct mail_sbuf out;
            const char *vstart;
            const char *q;
            char *trimmed;

            if (mail_sbuf_init(&out) == -1)
                return NULL;

            vstart = p + namelen + 1;
            if (mail_sbuf_putn(&out, vstart,
                               (size_t)((p + line_len) - vstart)) == -1) {
                free(out.data);
                return NULL;
            }

            q = (*line_end == '\n') ? line_end + 1 : line_end;
            while (q < headers_end && (*q == ' ' || *q == '\t')) {
                const char *cont_start;
                const char *cont_end;
                size_t cont_len;

                while (q < headers_end && (*q == ' ' || *q == '\t'))
                    q++;
                cont_start = q;

                cont_end = memchr(q, '\n', (size_t)(headers_end - q));
                if (cont_end == NULL)
                    cont_end = headers_end;

                cont_len = (size_t)(cont_end - cont_start);
                if (cont_len > 0 && cont_start[cont_len - 1] == '\r')
                    cont_len--;

                if (mail_sbuf_putc(&out, ' ') == -1 ||
                    mail_sbuf_putn(&out, cont_start, cont_len) == -1) {
                    free(out.data);
                    return NULL;
                }

                q = (*cont_end == '\n') ? cont_end + 1 : cont_end;
            }

            trimmed = mail_trim_dup(out.data, out.len);
            free(out.data);
            return trimmed;
        }

        p = (*line_end == '\n') ? line_end + 1 : line_end;
    }

    return NULL;
}

static char *
mail_latin1_to_utf8_dup(const char *in, size_t in_len)
{
    char *out;
    char *d;
    size_t i;

    out = malloc((in_len * 2) + 1);
    if (out == NULL)
        return NULL;

    d = out;
    for (i = 0; i < in_len; i++) {
        unsigned char c;

        c = (unsigned char)in[i];
        if (c < 0x80) {
            *d++ = (char)c;
        } else {
            *d++ = (char)(0xc0 | (c >> 6));
            *d++ = (char)(0x80 | (c & 0x3f));
        }
    }

    *d = '\0';
    return out;
}

static char *
mail_q_decode_word_dup(const char *src, size_t len)
{
    char *out;
    char *d;
    size_t i;

    out = malloc(len + 1);
    if (out == NULL)
        return NULL;

    d = out;
    for (i = 0; i < len; i++) {
        if (src[i] == '_') {
            *d++ = ' ';
        } else if (src[i] == '=' && i + 2 < len &&
                   hexval((unsigned char)src[i + 1]) >= 0 &&
                   hexval((unsigned char)src[i + 2]) >= 0) {
            int h1;
            int h2;

            h1 = hexval((unsigned char)src[i + 1]);
            h2 = hexval((unsigned char)src[i + 2]);
            *d++ = (char)((h1 << 4) | h2);
            i += 2;
        } else {
            *d++ = src[i];
        }
    }

    *d = '\0';
    return out;
}

static char *
mail_charset_to_utf8_dup(const char *charset, char *decoded)
{
    char *out;

    if (decoded == NULL)
        return NULL;

    if (charset == NULL || strcasecmp(charset, "utf-8") == 0 ||
        strcasecmp(charset, "utf8") == 0 ||
        strcasecmp(charset, "us-ascii") == 0)
        return decoded;

    if (strcasecmp(charset, "iso-8859-1") == 0 ||
        strcasecmp(charset, "latin1") == 0 ||
        strcasecmp(charset, "latin-1") == 0) {
        out = mail_latin1_to_utf8_dup(decoded, strlen(decoded));
        free(decoded);
        return out;
    }

    /* Unknown charset: keep bytes as-is rather than dropping the subject. */
    return decoded;
}

static char *
mail_decode_encoded_word_dup(const char *s, size_t *consumed)
{
    const char *charset_start;
    const char *charset_end;
    const char *enc_start;
    const char *text_start;
    const char *text_end;
    char *charset;
    char *decoded;
    char *utf8;
    size_t charset_len;
    size_t text_len;

    *consumed = 0;

    if (s[0] != '=' || s[1] != '?')
        return NULL;

    charset_start = s + 2;
    charset_end = strchr(charset_start, '?');
    if (charset_end == NULL || charset_end == charset_start)
        return NULL;

    enc_start = charset_end + 1;
    if (enc_start[0] == '\0' || enc_start[1] != '?')
        return NULL;

    text_start = enc_start + 2;
    text_end = strstr(text_start, "?=");
    if (text_end == NULL)
        return NULL;

    charset_len = (size_t)(charset_end - charset_start);
    charset = malloc(charset_len + 1);
    if (charset == NULL)
        return NULL;
    memcpy(charset, charset_start, charset_len);
    charset[charset_len] = '\0';

    text_len = (size_t)(text_end - text_start);

    if (enc_start[0] == 'B' || enc_start[0] == 'b') {
        char *tmp;

        tmp = malloc(text_len + 1);
        if (tmp == NULL) {
            free(charset);
            return NULL;
        }
        memcpy(tmp, text_start, text_len);
        tmp[text_len] = '\0';
        decoded = mail_base64_decode_dup(tmp);
        free(tmp);
    } else if (enc_start[0] == 'Q' || enc_start[0] == 'q') {
        decoded = mail_q_decode_word_dup(text_start, text_len);
    } else {
        free(charset);
        return NULL;
    }

    utf8 = mail_charset_to_utf8_dup(charset, decoded);
    free(charset);

    if (utf8 == NULL)
        return NULL;

    *consumed = (size_t)((text_end + 2) - s);
    return utf8;
}

char *
mail_rfc2047_decode_utf8_dup(const char *src)
{
    struct mail_sbuf out;
    const char *p;
    int last_was_encoded;

    if (src == NULL)
        return NULL;

    if (mail_sbuf_init(&out) == -1)
        return NULL;

    p = src;
    last_was_encoded = 0;

    while (*p) {
        char *word;
        size_t consumed;

        word = mail_decode_encoded_word_dup(p, &consumed);
        if (word != NULL) {
            if (mail_sbuf_putn(&out, word, strlen(word)) == -1) {
                free(word);
                free(out.data);
                return NULL;
            }
            free(word);
            p += consumed;
            last_was_encoded = 1;
            continue;
        }

        if (isspace((unsigned char)*p)) {
            const char *q;

            q = p;
            while (*q && isspace((unsigned char)*q))
                q++;

            word = mail_decode_encoded_word_dup(q, &consumed);
            if (word != NULL && last_was_encoded) {
                free(word);
                p = q;
                continue;
            }
            free(word);

            if (mail_sbuf_putn(&out, p, (size_t)(q - p)) == -1) {
                free(out.data);
                return NULL;
            }
            p = q;
            last_was_encoded = 0;
            continue;
        }

        if (mail_sbuf_putc(&out, *p) == -1) {
            free(out.data);
            return NULL;
        }
        p++;
        last_was_encoded = 0;
    }

    return out.data;
}

char *
mail_subject_utf8_dup(const char *msg)
{
    char *raw;
    char *decoded;

    raw = mail_header_value_dup(msg, "Subject");
    if (raw == NULL)
        return strdup("");

    decoded = mail_rfc2047_decode_utf8_dup(raw);
    free(raw);

    if (decoded == NULL)
        return strdup("");

    return decoded;
}

