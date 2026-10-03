/* sklaff_dependencies.h
 *
 * External dependencies used by optional SklaffKOM features.
 *
 * These defaults preserve legacy behaviour when SklaffKOM is built
 * without ./configure. A generated config.h may override them later.
 */

#ifndef SKLAFF_DEPENDENCIES_H
#define SKLAFF_DEPENDENCIES_H

#ifndef HAVE_FROTZ
#define HAVE_FROTZ 1
#endif

#ifndef HAVE_NETHACK
#define HAVE_NETHACK 1
#endif

#ifndef HAVE_CP437_WRAPPER
#define HAVE_CP437_WRAPPER 0
#endif

#endif /* SKLAFF_DEPENDENCIES_H */
