/* ftnconfig.c - CrashMail configuration reader for SklaffKOM */

#include "ftnconfig.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define FTNCONFIG_LINE_LEN 4096
#define FTNCONFIG_MAX_TOKENS 64

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
copy_string(char *dst, size_t dstsz, const char *src)
{
    size_t len;

    if (dst == NULL || dstsz == 0 || src == NULL)
        return -1;

    len = strlen(src);
    if (len >= dstsz)
        return -1;

    memcpy(dst, src, len + 1);
    return 0;
}

static int
tokenize_line(char *line, char **tokens, size_t maxtokens)
{
    char *p;
    size_t count;

    if (line == NULL || tokens == NULL || maxtokens == 0)
        return -1;

    p = line;
    count = 0;

    while (*p != '\0') {
        while (isspace((unsigned char)*p))
            p++;

        if (*p == '\0' || *p == ';')
            break;

        if (count == maxtokens)
            return -1;

        if (*p == '"') {
            p++;
            tokens[count++] = p;

            while (*p != '\0' && *p != '"')
                p++;

            if (*p != '"')
                return -1;

            *p++ = '\0';
        } else {
            tokens[count++] = p;

            while (*p != '\0' &&
                !isspace((unsigned char)*p) && *p != ';')
                p++;

            if (*p == ';') {
                *p = '\0';
                break;
            }

            if (*p != '\0')
                *p++ = '\0';
        }
    }

    return (int)count;
}

static int
parse_number(const char **text, long *value)
{
    char *end;
    long n;

    if (text == NULL || *text == NULL || value == NULL)
        return -1;

    errno = 0;
    n = strtol(*text, &end, 10);
    if (errno != 0 || end == *text || n < 0 || n > 65535)
        return -1;

    *text = end;
    *value = n;
    return 0;
}

void
ftn_config_init(struct ftn_config *config)
{
    if (config != NULL)
        memset(config, 0, sizeof(*config));
}

void
ftn_config_free(struct ftn_config *config)
{
    size_t i;

    if (config == NULL)
        return;

    for (i = 0; i < config->area_count; i++)
        free(config->areas[i].links);

    free(config->areas);
    free(config->akas);
    memset(config, 0, sizeof(*config));
}

int
ftn_address_parse(const char *text, struct ftn_address *address)
{
    const char *p;
    long zone;
    long net;
    long node;
    long point;

    if (text == NULL || address == NULL)
        return -1;

    p = text;
    point = 0;

    if (parse_number(&p, &zone) != 0 || *p++ != ':')
        return -1;
    if (parse_number(&p, &net) != 0 || *p++ != '/')
        return -1;
    if (parse_number(&p, &node) != 0)
        return -1;

    if (*p == '.') {
        p++;
        if (parse_number(&p, &point) != 0)
            return -1;
    }

    if (*p != '\0')
        return -1;

    address->zone = (int)zone;
    address->net = (int)net;
    address->node = (int)node;
    address->point = (int)point;
    return 0;
}

int
ftn_address_equal(const struct ftn_address *a, const struct ftn_address *b)
{
    if (a == NULL || b == NULL)
        return 0;

    return a->zone == b->zone &&
        a->net == b->net &&
        a->node == b->node &&
        a->point == b->point;
}

void
ftn_address_format(const struct ftn_address *address, char *out, size_t outsz)
{
    if (out == NULL || outsz == 0)
        return;

    if (address == NULL) {
        out[0] = '\0';
        return;
    }

    if (address->point == 0) {
        snprintf(out, outsz, "%d:%d/%d",
            address->zone, address->net, address->node);
    } else {
        snprintf(out, outsz, "%d:%d/%d.%d",
            address->zone, address->net, address->node,
            address->point);
    }
}

static struct ftn_aka *
append_aka(struct ftn_config *config)
{
    struct ftn_aka *newakas;
    struct ftn_aka *aka;

    newakas = realloc(config->akas,
        (config->aka_count + 1) * sizeof(*newakas));
    if (newakas == NULL)
        return NULL;

    config->akas = newakas;
    aka = &config->akas[config->aka_count++];
    memset(aka, 0, sizeof(*aka));
    return aka;
}

static struct ftn_area *
append_area(struct ftn_config *config)
{
    struct ftn_area *newareas;
    struct ftn_area *area;

    newareas = realloc(config->areas,
        (config->area_count + 1) * sizeof(*newareas));
    if (newareas == NULL)
        return NULL;

    config->areas = newareas;
    area = &config->areas[config->area_count++];
    memset(area, 0, sizeof(*area));
    return area;
}

static int
append_link(struct ftn_area *area, const char *text)
{
    struct ftn_link *newlinks;
    struct ftn_link link;
    const char *p;

    if (area == NULL || text == NULL || *text == '\0')
        return -1;

    memset(&link, 0, sizeof(link));
    p = text;

    if (*p == '!' || *p == '@' || *p == '%')
        link.modifier = *p++;

    /*
     * CrashMail also supports abbreviated EXPORT addresses.  The first
     * version deliberately accepts full 4D addresses only, so ftntoss never
     * guesses which node an abbreviation refers to.
     */
    if (ftn_address_parse(p, &link.address) != 0)
        return -1;

    newlinks = realloc(area->links,
        (area->link_count + 1) * sizeof(*newlinks));
    if (newlinks == NULL)
        return -1;

    area->links = newlinks;
    area->links[area->link_count++] = link;
    return 0;
}

static const struct ftn_aka *
find_aka(const struct ftn_config *config, const struct ftn_address *address)
{
    size_t i;

    if (config == NULL || address == NULL)
        return NULL;

    for (i = 0; i < config->aka_count; i++) {
        if (ftn_address_equal(&config->akas[i].address, address))
            return &config->akas[i];
    }

    return NULL;
}

static int
resolve_area_domains(struct ftn_config *config, const char *path,
    char *error, size_t errorsz)
{
    size_t i;

    for (i = 0; i < config->area_count; i++) {
        const struct ftn_aka *aka;
        struct ftn_area *area;
        char addr[64];

        area = &config->areas[i];
        aka = find_aka(config, &area->aka);
        if (aka == NULL) {
            ftn_address_format(&area->aka, addr, sizeof(addr));
            set_error(error, errorsz,
                "%s: area %s uses unknown AKA %s",
                path, area->tag, addr);
            return -1;
        }

        if (aka->domain[0] == '\0') {
            ftn_address_format(&area->aka, addr, sizeof(addr));
            set_error(error, errorsz,
                "%s: AKA %s used by area %s has no DOMAIN",
                path, addr, area->tag);
            return -1;
        }

        if (copy_string(area->domain, sizeof(area->domain),
                aka->domain) != 0) {
            set_error(error, errorsz,
                "%s: DOMAIN is too long for area %s", path, area->tag);
            return -1;
        }
    }

    return 0;
}

int
ftn_config_load_crashmail(const char *path, struct ftn_config *config,
    char *error, size_t errorsz)
{
    struct ftn_config parsed;
    struct ftn_aka *current_aka;
    struct ftn_area *current_area;
    FILE *fp;
    char line[FTNCONFIG_LINE_LEN];
    unsigned long lineno;

    if (path == NULL || config == NULL) {
        set_error(error, errorsz, "invalid argument");
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        set_error(error, errorsz, "%s: %s", path, strerror(errno));
        return -1;
    }

    ftn_config_init(&parsed);
    current_aka = NULL;
    current_area = NULL;
    lineno = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *tokens[FTNCONFIG_MAX_TOKENS];
        int ntokens;
        int i;

        lineno++;

        if (strchr(line, '\n') == NULL && !feof(fp)) {
            set_error(error, errorsz,
                "%s:%lu: line exceeds %d bytes",
                path, lineno, FTNCONFIG_LINE_LEN - 1);
            goto fail;
        }

        ntokens = tokenize_line(line, tokens, FTNCONFIG_MAX_TOKENS);
        if (ntokens < 0) {
            set_error(error, errorsz,
                "%s:%lu: malformed or overlong configuration line",
                path, lineno);
            goto fail;
        }

        if (ntokens == 0)
            continue;

        if (strcasecmp(tokens[0], "AKA") == 0) {
            if (ntokens < 2) {
                set_error(error, errorsz,
                    "%s:%lu: AKA requires an address", path, lineno);
                goto fail;
            }

            current_aka = append_aka(&parsed);
            if (current_aka == NULL) {
                set_error(error, errorsz, "%s:%lu: out of memory",
                    path, lineno);
                goto fail;
            }

            if (ftn_address_parse(tokens[1], &current_aka->address) != 0) {
                set_error(error, errorsz,
                    "%s:%lu: invalid AKA address: %s",
                    path, lineno, tokens[1]);
                goto fail;
            }

            current_area = NULL;
            continue;
        }

        if (strcasecmp(tokens[0], "DOMAIN") == 0) {
            if (ntokens < 2 || current_aka == NULL) {
                set_error(error, errorsz,
                    "%s:%lu: DOMAIN must follow an AKA",
                    path, lineno);
                goto fail;
            }

            if (copy_string(current_aka->domain,
                    sizeof(current_aka->domain), tokens[1]) != 0) {
                set_error(error, errorsz,
                    "%s:%lu: DOMAIN is too long", path, lineno);
                goto fail;
            }
            continue;
        }

        if (strcasecmp(tokens[0], "AREA") == 0 ||
            strcasecmp(tokens[0], "NETMAIL") == 0 ||
            strcasecmp(tokens[0], "LOCALAREA") == 0) {
            if (ntokens < 3) {
                set_error(error, errorsz,
                    "%s:%lu: %s requires a tag and AKA",
                    path, lineno, tokens[0]);
                goto fail;
            }

            current_area = append_area(&parsed);
            if (current_area == NULL) {
                set_error(error, errorsz, "%s:%lu: out of memory",
                    path, lineno);
                goto fail;
            }

            if (strcasecmp(tokens[0], "AREA") == 0)
                current_area->type = FTN_AREA_ECHOMAIL;
            else if (strcasecmp(tokens[0], "NETMAIL") == 0)
                current_area->type = FTN_AREA_NETMAIL;
            else
                current_area->type = FTN_AREA_LOCAL;

            if (copy_string(current_area->tag,
                    sizeof(current_area->tag), tokens[1]) != 0) {
                set_error(error, errorsz,
                    "%s:%lu: area tag is too long", path, lineno);
                goto fail;
            }

            if (ftn_address_parse(tokens[2], &current_area->aka) != 0) {
                set_error(error, errorsz,
                    "%s:%lu: invalid area AKA: %s",
                    path, lineno, tokens[2]);
                goto fail;
            }

            if (ntokens >= 4 &&
                copy_string(current_area->messagebase,
                    sizeof(current_area->messagebase), tokens[3]) != 0) {
                set_error(error, errorsz,
                    "%s:%lu: messagebase name is too long", path, lineno);
                goto fail;
            }

            if (ntokens >= 5 &&
                copy_string(current_area->path,
                    sizeof(current_area->path), tokens[4]) != 0) {
                set_error(error, errorsz,
                    "%s:%lu: area path is too long", path, lineno);
                goto fail;
            }

            current_aka = NULL;
            continue;
        }

        if (strcasecmp(tokens[0], "EXPORT") == 0) {
            if (current_area == NULL ||
                current_area->type != FTN_AREA_ECHOMAIL) {
                set_error(error, errorsz,
                    "%s:%lu: EXPORT must follow an AREA",
                    path, lineno);
                goto fail;
            }

            for (i = 1; i < ntokens; i++) {
                if (append_link(current_area, tokens[i]) != 0) {
                    set_error(error, errorsz,
                        "%s:%lu: unsupported or invalid EXPORT address: %s; "
                        "use a full zone:net/node.point address",
                        path, lineno, tokens[i]);
                    goto fail;
                }
            }
            continue;
        }
    }

    if (ferror(fp)) {
        set_error(error, errorsz, "%s: read error: %s",
            path, strerror(errno));
        goto fail;
    }

    fclose(fp);
    fp = NULL;

    if (resolve_area_domains(&parsed, path, error, errorsz) != 0)
        goto fail;

    ftn_config_free(config);
    *config = parsed;
    if (error != NULL && errorsz > 0)
        error[0] = '\0';
    return 0;

fail:
    if (fp != NULL)
        fclose(fp);
    ftn_config_free(&parsed);
    return -1;
}

const struct ftn_area *
ftn_config_find_area(const struct ftn_config *config,
    const char *domain, const char *tag)
{
    size_t i;

    if (config == NULL || tag == NULL)
        return NULL;

    for (i = 0; i < config->area_count; i++) {
        const struct ftn_area *area;

        area = &config->areas[i];
        if (strcasecmp(area->tag, tag) != 0)
            continue;

        if (domain == NULL || *domain == '\0' ||
            strcasecmp(area->domain, domain) == 0)
            return area;
    }

    return NULL;
}

const struct ftn_link *
ftn_area_primary_feed(const struct ftn_area *area)
{
    size_t i;

    if (area == NULL || area->link_count == 0)
        return NULL;

    for (i = 0; i < area->link_count; i++) {
        if (area->links[i].modifier == '%')
            return &area->links[i];
    }

    if (area->link_count == 1)
        return &area->links[0];

    return NULL;
}

static const char *
area_type_name(enum ftn_area_type type)
{
    switch (type) {
    case FTN_AREA_ECHOMAIL:
        return "echomail";
    case FTN_AREA_NETMAIL:
        return "netmail";
    case FTN_AREA_LOCAL:
        return "local";
    default:
        return "unknown";
    }
}

void
ftn_config_dump(FILE *out, const struct ftn_config *config)
{
    size_t i;

    if (out == NULL || config == NULL)
        return;

    fprintf(out, "CrashMail FTN configuration\n");
    fprintf(out, "===========================\n\n");

    fprintf(out, "AKAs: %lu\n", (unsigned long)config->aka_count);
    for (i = 0; i < config->aka_count; i++) {
        char addr[64];

        ftn_address_format(&config->akas[i].address, addr, sizeof(addr));
        fprintf(out, "  %-18s domain=%s\n", addr,
            config->akas[i].domain[0] ? config->akas[i].domain : "(missing)");
    }

    fprintf(out, "\nAreas: %lu\n", (unsigned long)config->area_count);
    for (i = 0; i < config->area_count; i++) {
        const struct ftn_area *area;
        const struct ftn_link *feed;
        char aka[64];
        char feedaddr[64];

        area = &config->areas[i];
        feed = ftn_area_primary_feed(area);
        ftn_address_format(&area->aka, aka, sizeof(aka));

        if (feed != NULL)
            ftn_address_format(&feed->address, feedaddr, sizeof(feedaddr));
        else
            copy_string(feedaddr, sizeof(feedaddr), "(none/ambiguous)");

        fprintf(out, "\n  Tag:         %s\n", area->tag);
        fprintf(out, "  Type:        %s\n", area_type_name(area->type));
        fprintf(out, "  Domain:      %s\n", area->domain);
        fprintf(out, "  AKA:         %s\n", aka);
        fprintf(out, "  Messagebase: %s\n",
            area->messagebase[0] ? area->messagebase : "(not specified)");
        fprintf(out, "  Path:        %s\n",
            area->path[0] ? area->path : "(not specified)");
        fprintf(out, "  Feed:        %s\n", feedaddr);
    }
}
