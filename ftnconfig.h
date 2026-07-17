#ifndef FTNCONFIG_H
#define FTNCONFIG_H

#include <stddef.h>
#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define FTN_DOMAIN_LEN 64
#define FTN_TAG_LEN 128
#define FTN_MSGBASE_LEN 32

struct ftn_address {
    int zone;
    int net;
    int node;
    int point;
};

struct ftn_aka {
    struct ftn_address address;
    char domain[FTN_DOMAIN_LEN];
};

enum ftn_area_type {
    FTN_AREA_ECHOMAIL = 1,
    FTN_AREA_NETMAIL = 2,
    FTN_AREA_LOCAL = 3
};

struct ftn_link {
    struct ftn_address address;
    char modifier;
};

struct ftn_area {
    enum ftn_area_type type;
    char tag[FTN_TAG_LEN];
    char domain[FTN_DOMAIN_LEN];
    char messagebase[FTN_MSGBASE_LEN];
    char path[PATH_MAX];
    struct ftn_address aka;
    struct ftn_link *links;
    size_t link_count;
};

struct ftn_config {
    struct ftn_aka *akas;
    size_t aka_count;
    struct ftn_area *areas;
    size_t area_count;
};

void ftn_config_init(struct ftn_config *config);
void ftn_config_free(struct ftn_config *config);

int ftn_address_parse(const char *text, struct ftn_address *address);
int ftn_address_equal(const struct ftn_address *a,
    const struct ftn_address *b);
void ftn_address_format(const struct ftn_address *address,
    char *out, size_t outsz);

int ftn_config_load_crashmail(const char *path, struct ftn_config *config,
    char *error, size_t errorsz);

const struct ftn_area *ftn_config_find_area(const struct ftn_config *config,
    const char *domain, const char *tag);

const struct ftn_link *ftn_area_primary_feed(const struct ftn_area *area);

void ftn_config_dump(FILE *out, const struct ftn_config *config);

#endif
