#ifndef MAILBODY_H
#define MAILBODY_H

/*
 * mailbody.h - extract and render the best readable body from an RFC822/MIME
 * message.  The returned string is UTF-8 and must be freed by the caller.
 */

#define MAILBODY_CLEANUP 0x01
#define MAILBODY_VERBOSE 0x02

char *mailbody_render_utf8_dup(const char *msg, int clean, int verbose);
char *mailbody_render_utf8_opts_dup(const char *msg, int flags);

#endif /* MAILBODY_H */
