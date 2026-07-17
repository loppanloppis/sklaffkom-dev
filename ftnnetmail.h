#ifndef FTNNETMAIL_H
#define FTNNETMAIL_H

#include "ftnmsg.h"

int import_ftn_netmail_spool(const char *spooldir); /* modified on 2026-07-09, PL */
int send_netmail(int uid, const struct fido_msg *msg); /* modified on 2026-07-09, PL */

int import_ftn_netmail_spool_5d(const char *spooldir,
    const char *domain, const char *local_addr);

#endif
