/* sklaff_programs.h
 *
 * Paths to external programs used by SklaffKOM.
 *
 * These defaults preserve legacy behaviour when SklaffKOM is built
 * without ./configure. A generated config.h may override them.
 */

#ifndef SKLAFF_PROGRAMS_H
#define SKLAFF_PROGRAMS_H

#ifndef FROTZ_BIN
#define FROTZ_BIN "/usr/local/bin/frotz"
#endif

#ifndef NETHACK_BIN
#define NETHACK_BIN "/usr/local/bin/nethack"
#endif

#ifndef CP437_WRAPPER
#define CP437_WRAPPER "/usr/local/bin/cp437"
#endif

#endif /* SKLAFF_PROGRAMS_H */
