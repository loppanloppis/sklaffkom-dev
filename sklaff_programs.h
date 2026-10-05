/* sklaff_programs.h
 *
 * External programs used by SklaffKOM.
 *
 * These defaults preserve legacy behaviour when SklaffKOM is built
 * without ./configure. A generated config.h may override them.
 */

#ifndef SKLAFF_PROGRAMS_H
#define SKLAFF_PROGRAMS_H

/* Frotz / Zork */
#ifndef FROTZ_BIN
#define FROTZ_BIN "/usr/local/bin/frotz"
#endif

#ifndef FROTZ_ARGS
#define FROTZ_ARGS "-D 0 -Z 0 -R"
#endif

/* Nethack */
#ifndef NETHACK_BIN
#define NETHACK_BIN "/usr/local/bin/nethack"
#endif

/* CP437 wrapper used by BBSLink for UTF-8 sessions */
#ifndef CP437_WRAPPER
#define CP437_WRAPPER "/usr/local/bin/cp437"
#endif

/* QWK packer */
#ifndef ZIP_BIN
#define ZIP_BIN "/usr/bin/zip"
#endif

#ifndef ZIP_ARGS
#define ZIP_ARGS "-9"
#endif

/* Usenet posting */
#ifndef INEWS_BIN
#define INEWS_BIN "/usr/local/bin/inews"
#endif

#ifndef INEWS_ARGS
#define INEWS_ARGS "-h -S -P"
#endif

/* Software for uploads and downloads. 
Please read item 18 for instructions here: 
https://github.com/joakimmelin/sklaffkom/wiki/Install-Instructions */

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

#endif /* SKLAFF_PROGRAMS_H */
