/* sklaff_programs.h
 *
 * External programs used by SklaffKOM.
 *
 * These defaults preserve legacy behaviour when SklaffKOM is built
 * without ./configure. A generated config.h may override them.
 * 2026-10-06 PL
 */

#ifndef SKLAFF_PROGRAMS_H
#define SKLAFF_PROGRAMS_H


/*
 * Core runtime tools
 */

/* Search for text strings in articles */
#ifndef GREP_BIN
#define GREP_BIN "/usr/bin/grep"
#endif

#ifndef GREP_ARGS
#define GREP_ARGS "-i -F"
#endif

/* File listings */
#ifndef LS_BIN
#define LS_BIN "/bin/ls"
#endif

#ifndef LS_ARGS
#define LS_ARGS "-1"
#endif

/* Print text to standard output */
#ifndef ECHO_BIN
#define ECHO_BIN "/bin/echo"
#endif

/* Change user password */
#ifndef PASSWD_BIN
#define PASSWD_BIN "/usr/bin/passwd"
#endif


/*
 * Optional transport methods
 */

/* Usenet posting */
#ifndef INEWS_ARGS
#define INEWS_ARGS "-h -S -P"
#endif

/* ZMODEM file transfers */
#ifndef LRZ_BIN
#define LRZ_BIN "/usr/local/bin/lrz"
#endif

#ifndef LRZ_ARGS
#define LRZ_ARGS "-Eq"
#endif

#ifndef LSZ_BIN
#define LSZ_BIN "/usr/local/bin/lsz"
#endif

#ifndef LSZ_ARGS
#define LSZ_ARGS "-Eq"
#endif

/*
 * Optional utilities
 */

/* Schedule commands for later execution */
#ifndef AT_BIN
#define AT_BIN "/usr/bin/at"
#endif

/* QWK packer */
#ifndef ZIP_BIN
#define ZIP_BIN "/usr/bin/zip"
#endif

#ifndef ZIP_ARGS
#define ZIP_ARGS "-9"
#endif

#ifndef SURVREPORT
#define SURVREPORT SKLAFFBIN "/srep"
#endif

#ifndef CHFN_BIN
#define CHFN_BIN "/usr/bin/chfn"
#endif

/* Nethack */
#ifndef NETHACK_BIN
#define NETHACK_BIN "/usr/local/bin/nethack"
#endif

#endif /* SKLAFF_PROGRAMS_H */
