/* sklaff_features.h
 *
 * Optional SklaffKOM features.
 *
 * Set features to 1 to enable or 0 to disable.
 * Dependencies may still be required for an enabled feature.
 */

#ifndef SKLAFF_FEATURES_H
#define SKLAFF_FEATURES_H

/* Optional transport methods */

#ifndef ENABLE_OUTBOUND_EMAIL
#define ENABLE_OUTBOUND_EMAIL 1
#endif

#ifndef ENABLE_USENET_POSTING
#define ENABLE_USENET_POSTING 1
#endif

/* InterBBS Oneliner wall and importer; configure overrides this default. */
#ifndef ENABLE_IBOL
#define ENABLE_IBOL 0
#endif

/* Optional games / doors */

/*
 * BBSLink door games.
 *
 * Requires a working BBSLink installation.
 * UTF-8 sessions also require the CP437 wrapper.
 */
#ifndef ENABLE_BBSLINK
#define ENABLE_BBSLINK 1
#endif

/*
 * Zork / Infocom games.
 *
 * Requires Frotz and the appropriate game data files.
 */
#ifndef ENABLE_ZORK
#define ENABLE_ZORK 1
#endif

/*
 * Nethack.
 *
 * Requires a working Nethack executable.
 */
#ifndef ENABLE_NETHACK
#define ENABLE_NETHACK 1
#endif

/*
 * QWK batch download support.
 *
 * This feature is disabled by default until the legacy QWK
 * implementation has been tested on modern systems.
 */
#ifndef ENABLE_QWK
#define ENABLE_QWK 0
#endif

#endif /* SKLAFF_FEATURES_H */
