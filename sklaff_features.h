/* sklaff_features.h
 *
 * Optional SklaffKOM features.
 *
 * Set features to 1 to enable or 0 to disable.
 * Dependencies may still be required for an enabled feature.
 */

#ifndef SKLAFF_FEATURES_H
#define SKLAFF_FEATURES_H

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
