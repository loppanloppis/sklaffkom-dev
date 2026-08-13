/* ftnnetmail.c - import FTN netmail into local SklaffKOM mailboxes */

#include "sklaff.h"
#include "ftnmsg.h"
#include "ftnnetmail.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define FTNNETMAIL_SKLAFF_OWNER "sklaff" /* modified on 2026-07-09, PL */

struct mailbox_conf_entry {
    int num;
    long last_text;
    int creator;
    long time;
    int type;
    int life;
    int comconf;
    char name[256];
};

static int is_msg_file(const char *name);
static void normalize_netmail_name(const char *in, char *out, size_t outsz);
static int mailbox_file_for_uid(int uid, char *out, size_t outsz);
static int mailbox_dir_for_uid(int uid, char *out, size_t outsz);
static int local_mailbox_exists(int uid);
static int find_netmail_user(const char *to_name);
static int parse_mailbox_conf_line(const char *line, struct mailbox_conf_entry *ce);
static int read_mailbox_last_text(int uid, long *last_text);
static int rewrite_mailbox_last_text(int uid, long *new_textnum);
static long count_lines(const char *s);
static int ftn_chrs_is_utf8(const char *chrs);
static char *netmail_to_sf7_dup(const char *src, const char *chrs);
static int netmail_already_imported(int uid, const char *domain,
    const char *msgid);
static void ftn_msgid_origin(const char *msgid, char *out, size_t outsz);
static void make_ftn_5d_addr(const char *addr, const char *domain,
    char *out, size_t outsz);
static char *build_netmail_mbuf(const struct fido_msg *msg,
    const char *domain, const char *local_addr);
static int send_netmail_with_context(int uid, const struct fido_msg *msg,
    const char *domain, const char *local_addr);
static void notify_netmail_user(int uid, int sig);

static int
is_msg_file(const char *name)
{
    const char *dot;

    if (name == NULL)
        return 0;

    dot = strrchr(name, '.');
    if (dot == NULL)
        return 0;

    return strcasecmp(dot, ".msg") == 0;
}

static void
normalize_netmail_name(const char *in, char *out, size_t outsz)
{
    size_t n = 0;
    int inspace = 1;

    if (out == NULL || outsz == 0)
        return;

    out[0] = '\0';

    if (in == NULL)
        return;

    while (*in != '\0' && n + 1 < outsz) {
        unsigned char ch = (unsigned char)*in;

        if (ch == ',')
            break;

        if (isspace(ch)) {
            if (!inspace && n + 1 < outsz) {
                out[n++] = ' ';
                inspace = 1;
            }
        } else if (ch != '.') {
            out[n++] = (char)tolower(ch);
            inspace = 0;
        }

        in++;
    }

    while (n > 0 && out[n - 1] == ' ')
        n--;

    out[n] = '\0';
}

static int
mailbox_dir_for_uid(int uid, char *out, size_t outsz)
{
    if (out == NULL || outsz == 0)
        return -1;

    if (snprintf(out, outsz, "%s/mbox/%d/", SKLAFFDIR, uid) >= (int)outsz)
        return -1;

    return 0;
}

static int
mailbox_file_for_uid(int uid, char *out, size_t outsz)
{
    char dir[PATH_MAX];

    if (mailbox_dir_for_uid(uid, dir, sizeof(dir)) != 0)
        return -1;

    if (snprintf(out, outsz, "%s%s", dir, MAILBOX_FILE) >= (int)outsz)
        return -1;

    return 0;
}

static int
local_mailbox_exists(int uid)
{
    char path[PATH_MAX];
    struct stat st;

    if (mailbox_file_for_uid(uid, path, sizeof(path)) != 0)
        return 0;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int
find_netmail_user(const char *to_name)
{
    struct passwd *pw;
    char wanted[256];
    char candidate[256];
    char gecos[256];

    normalize_netmail_name(to_name, wanted, sizeof(wanted));
    if (wanted[0] == '\0')
        return -1;

    setpwent();
    while ((pw = getpwent()) != NULL) {
        if (!local_mailbox_exists((int)pw->pw_uid))
            continue;

        normalize_netmail_name(pw->pw_gecos, candidate, sizeof(candidate));
        if (candidate[0] != '\0' && strcmp(candidate, wanted) == 0) {
            endpwent();
            return (int)pw->pw_uid;
        }

        /* Also allow matching the Unix login name as a fallback. */
        normalize_netmail_name(pw->pw_name, candidate, sizeof(candidate));
        if (candidate[0] != '\0' && strcmp(candidate, wanted) == 0) {
            endpwent();
            return (int)pw->pw_uid;
        }

        /* Some GECOS fields contain commas; try the part before comma only. */
        memset(gecos, 0, sizeof(gecos));
        snprintf(gecos, sizeof(gecos), "%s", pw->pw_gecos ? pw->pw_gecos : "");
        if (strchr(gecos, ',') != NULL)
            *strchr(gecos, ',') = '\0';
        normalize_netmail_name(gecos, candidate, sizeof(candidate));
        if (candidate[0] != '\0' && strcmp(candidate, wanted) == 0) {
            endpwent();
            return (int)pw->pw_uid;
        }
    }
    endpwent();

    return -1;
}

static int
parse_mailbox_conf_line(const char *line, struct mailbox_conf_entry *ce)
{
    char name[256];

    if (line == NULL || ce == NULL)
        return -1;

    memset(ce, 0, sizeof(*ce));
    memset(name, 0, sizeof(name));

    if (sscanf(line, "%d:%ld:%d:%ld:%d:%d:%d:%255[^\n]",
            &ce->num,
            &ce->last_text,
            &ce->creator,
            &ce->time,
            &ce->type,
            &ce->life,
            &ce->comconf,
            name) != 8) {
        return -1;
    }

    snprintf(ce->name, sizeof(ce->name), "%s", name);
    return 0;
}

static int
read_mailbox_last_text(int uid, long *last_text)
{
    FILE *fp;
    char path[PATH_MAX];
    char line[1024];

    if (last_text == NULL)
        return -1;

    *last_text = 0;

    if (mailbox_file_for_uid(uid, path, sizeof(path)) != 0)
        return -1;

    fp = fopen(path, "r");
    if (fp == NULL)
        return -1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        struct mailbox_conf_entry ce;

        if (parse_mailbox_conf_line(line, &ce) == 0 && ce.num == 0) {
            *last_text = ce.last_text;
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

static int
rewrite_mailbox_last_text(int uid, long *new_textnum)
{
    FILE *in;
    FILE *out;
    char path[PATH_MAX];
    char tmpfile[PATH_MAX];
    char line[1024];
    struct stat mailbox_st;
    int outfd;
    int found = 0;

    if (new_textnum == NULL)
        return -1;

    if (mailbox_file_for_uid(uid, path, sizeof(path)) != 0)
        return -1;

    if (stat(path, &mailbox_st) != 0)
        return -1;

    if (snprintf(tmpfile, sizeof(tmpfile), "%s.ftnnetmail.tmp", path) >=
            (int)sizeof(tmpfile))
        return -1;

    in = fopen(path, "r");
    if (in == NULL)
        return -1;

    out = fopen(tmpfile, "w");
    if (out == NULL) {
        fclose(in);
        return -1;
    }

    /*
     * The mailbox control file is replaced through rename().  Preserve its
     * ownership and mode so a sudo/root import cannot leave a root-owned
     * mailbox file behind.
     *
     * modified on 2026-07-16, PL
     */
    outfd = fileno(out);
    if (outfd == -1) {
        fclose(in);
        fclose(out);
        unlink(tmpfile);
        return -1;
    }

    if (geteuid() == 0) {
        if (fchown(outfd, mailbox_st.st_uid, mailbox_st.st_gid) != 0) {
            fclose(in);
            fclose(out);
            unlink(tmpfile);
            return -1;
        }
    } else if (geteuid() != mailbox_st.st_uid) {
        fprintf(stderr,
            "[ERROR] Cannot safely rewrite mailbox %s as uid %ld\n",
            path, (long)geteuid());
        fclose(in);
        fclose(out);
        unlink(tmpfile);
        return -1;
    }

    if (fchmod(outfd, mailbox_st.st_mode & 07777) != 0) {
        fclose(in);
        fclose(out);
        unlink(tmpfile);
        return -1;
    }

    while (fgets(line, sizeof(line), in) != NULL) {
        struct mailbox_conf_entry ce;

        if (parse_mailbox_conf_line(line, &ce) == 0 && ce.num == 0) {
            ce.last_text++;
            *new_textnum = ce.last_text;
            found = 1;

            fprintf(out, "%d:%ld:%d:%ld:%d:%d:%d:%s\n",
                ce.num,
                ce.last_text,
                ce.creator,
                ce.time,
                ce.type,
                ce.life,
                ce.comconf,
                ce.name);
        } else {
            fputs(line, out);
        }
    }

    if (fclose(in) != 0) {
        fclose(out);
        unlink(tmpfile);
        return -1;
    }

    if (fclose(out) != 0) {
        unlink(tmpfile);
        return -1;
    }

    if (!found) {
        unlink(tmpfile);
        return -1;
    }

    if (rename(tmpfile, path) != 0) {
        unlink(tmpfile);
        return -1;
    }

    return 0;
}

static long
count_lines(const char *s)
{
    long lines = 0;

    if (s == NULL)
        return 0;

    while (*s != '\0') {
        if (*s == '\n')
            lines++;
        s++;
    }

    return lines;
}

static int
ftn_chrs_is_utf8(const char *chrs)
{
    const char *p;

    if (chrs == NULL)
        return 0;

    p = chrs;
    while (*p == ' ' || *p == '\t')
        p++;

    /*
     * CHRS commonly arrives as "UTF-8 4".  Accept UTF8 as well, but do
     * not guess when CHRS is missing or declares another character set.
     *
     * modified on 2026-08-10, PL
     */
    if (strncasecmp(p, "UTF-8", 5) == 0 &&
        (p[5] == '\0' || isspace((unsigned char)p[5])))
        return 1;

    if (strncasecmp(p, "UTF8", 4) == 0 &&
        (p[4] == '\0' || isspace((unsigned char)p[4])))
        return 1;

    return 0;
}

static char *
netmail_to_sf7_dup(const char *src, const char *chrs)
{
    if (src == NULL)
        src = "";

    /*
     * SklaffKOM mailbox texts are still stored internally as SF7.  Convert
     * declared UTF-8 netmail at the import boundary, just like mailtoss does
     * for ordinary Internet mail.  Unknown/legacy FTN character sets are
     * preserved for now rather than guessed incorrectly.
     *
     * modified on 2026-08-10, PL
     */
    if (ftn_chrs_is_utf8(chrs))
        return utf8_to_sf7_dup(src);

    return strdup(src);
}

static int
netmail_already_imported(int uid, const char *domain, const char *msgid)
{
    char dir[PATH_MAX];
    char path[PATH_MAX];
    char line[1024];
    char msgid_needle[512];
    long last_text = 0;
    long i;

    if (msgid == NULL || *msgid == '\0')
        return 0;

    if (read_mailbox_last_text(uid, &last_text) != 0)
        return 0;

    if (mailbox_dir_for_uid(uid, dir, sizeof(dir)) != 0)
        return 0;

    snprintf(msgid_needle, sizeof(msgid_needle), "FTN-MSGID: %s", msgid);

    for (i = 1; i <= last_text; i++) {
        FILE *fp;
        int msgid_match;
        int domain_seen;
        int domain_match;

        if (snprintf(path, sizeof(path), "%s%ld", dir, i) >=
                (int)sizeof(path))
            continue;

        fp = fopen(path, "r");
        if (fp == NULL)
            continue;

        msgid_match = 0;
        domain_seen = 0;
        domain_match = 0;

        while (fgets(line, sizeof(line), fp) != NULL) {
            char *value;

            line[strcspn(line, "\r\n")] = '\0';

            if (strcmp(line, msgid_needle) == 0) {
                msgid_match = 1;
                continue;
            }

            if (strncmp(line, "FTN-Domain:", 11) != 0)
                continue;

            value = line + 11;
            while (*value == ' ' || *value == '\t')
                value++;

            domain_seen = 1;
            if (domain != NULL && *domain != '\0' &&
                strcasecmp(value, domain) == 0)
                domain_match = 1;
        }

        fclose(fp);

        /*
         * Old imported netmail has no FTN-Domain line.  Treat a matching
         * old MSGID as a duplicate for upgrade compatibility.  New mail is
         * compared as domain + MSGID so overlapping private FTN addresses
         * do not collide.
         *
         * modified on 2026-07-16, PL
         */
        if (msgid_match &&
            (domain == NULL || *domain == '\0' ||
             !domain_seen || domain_match))
            return 1;
    }

    return 0;
}

static void
ftn_msgid_origin(const char *msgid, char *out, size_t outsz)
{
    const char *p;
    size_t len;

    if (out == NULL || outsz == 0)
        return;

    out[0] = '\0';

    if (msgid == NULL || *msgid == '\0')
        return;

    p = msgid;
    while (*p != '\0' && !isspace((unsigned char)*p))
        p++;

    len = (size_t)(p - msgid);
    if (len >= outsz)
        len = outsz - 1;

    memcpy(out, msgid, len);
    out[len] = '\0';
}

static void
make_ftn_5d_addr(const char *addr, const char *domain,
    char *out, size_t outsz)
{
    if (out == NULL || outsz == 0)
        return;

    out[0] = '\0';

    if (addr == NULL || *addr == '\0')
        return;

    if (strchr(addr, '@') != NULL || domain == NULL || *domain == '\0') {
        strlcpy(out, addr, outsz);
        return;
    }

    snprintf(out, outsz, "%s@%s", addr, domain);
}

static char *
build_netmail_mbuf(const struct fido_msg *msg, const char *domain,
    const char *local_addr)
{
    char fromaddr4d[128];
    char fromaddr[192];
    char toaddr[192];
    char fromline[512];
    const char *body;
    size_t need;
    char *mbuf;
    char *from_sf7;
    char *to_sf7;
    char *subject_sf7;
    char *body_sf7;

    if (msg == NULL)
        return NULL;

    body = msg->clean_body;
    if (body == NULL)
        body = msg->raw_body;
    if (body == NULL)
        body = "";

    /*
     * The FTN parser deliberately leaves message bytes in their declared
     * external charset.  Mailbox storage, however, still follows SklaffKOM's
     * internal SF7 convention.  Normalize user-visible UTF-8 fields here, at
     * the import boundary, while leaving routing metadata untouched.
     *
     * modified on 2026-08-10, PL
     */
    from_sf7 = netmail_to_sf7_dup(
        msg->from[0] ? msg->from : "(unknown)", msg->chrs);
    to_sf7 = netmail_to_sf7_dup(msg->to, msg->chrs);
    subject_sf7 = netmail_to_sf7_dup(msg->subject, msg->chrs);
    body_sf7 = netmail_to_sf7_dup(body, msg->chrs);

    if (from_sf7 == NULL || to_sf7 == NULL ||
        subject_sf7 == NULL || body_sf7 == NULL) {
        free(from_sf7);
        free(to_sf7);
        free(subject_sf7);
        free(body_sf7);
        return NULL;
    }

    ftn_msgid_origin(msg->msgid, fromaddr4d, sizeof(fromaddr4d));
    make_ftn_5d_addr(fromaddr4d, domain, fromaddr, sizeof(fromaddr));
    make_ftn_5d_addr(local_addr, domain, toaddr, sizeof(toaddr));

    /*
     * Store a canonical 5D origin address in the visible From: line and in
     * hidden FTN metadata.  A later personal comment can then route a reply
     * through the same FTN domain instead of guessing from a 4D address.
     *
     * modified on 2026-07-16, PL
     */
    if (fromaddr[0] != '\0') {
        snprintf(fromline, sizeof(fromline), "%s (%s)",
            from_sf7, fromaddr);
    } else {
        snprintf(fromline, sizeof(fromline), "%s", from_sf7);
    }

    need = 1024;
    need += strlen(fromline);
    need += strlen(to_sf7);
    need += strlen(subject_sf7);
    need += strlen(msg->date);
    need += strlen(msg->msgid);
    need += strlen(msg->reply);
    need += strlen(msg->chrs);
    need += strlen(fromaddr);
    need += strlen(toaddr);
    need += strlen(body_sf7);
    if (domain != NULL)
        need += strlen(domain);

    mbuf = calloc(1, need);
    if (mbuf == NULL) {
        free(from_sf7);
        free(to_sf7);
        free(subject_sf7);
        free(body_sf7);
        return NULL;
    }

    snprintf(mbuf, need,
        "From: %s\n"
        "To: %s\n"
        "Subject: %s\n"
        "Date: %s\n"
        "FTN-Netmail: yes\n",
        fromline,
        to_sf7,
        subject_sf7,
        msg->date);

    if (domain != NULL && *domain != '\0') {
        strlcat(mbuf, "FTN-Domain: ", need);
        strlcat(mbuf, domain, need);
        strlcat(mbuf, "\n", need);
    }

    if (fromaddr[0] != '\0') {
        strlcat(mbuf, "FTN-FromAddr: ", need);
        strlcat(mbuf, fromaddr, need);
        strlcat(mbuf, "\n", need);
    }

    if (toaddr[0] != '\0') {
        strlcat(mbuf, "FTN-ToAddr: ", need);
        strlcat(mbuf, toaddr, need);
        strlcat(mbuf, "\n", need);
    }

    if (msg->msgid[0] != '\0') {
        strlcat(mbuf, "FTN-MSGID: ", need);
        strlcat(mbuf, msg->msgid, need);
        strlcat(mbuf, "\n", need);
    }

    if (msg->reply[0] != '\0') {
        strlcat(mbuf, "FTN-REPLY: ", need);
        strlcat(mbuf, msg->reply, need);
        strlcat(mbuf, "\n", need);
    }

    if (msg->chrs[0] != '\0') {
        strlcat(mbuf, "FTN-CHRS: ", need);
        strlcat(mbuf, msg->chrs, need);
        strlcat(mbuf, "\n", need);
    }

    strlcat(mbuf, "\n", need);
    strlcat(mbuf, body_sf7, need);

    free(from_sf7);
    free(to_sf7);
    free(subject_sf7);
    free(body_sf7);

    return mbuf;
}

static int
send_netmail_with_context(int uid, const struct fido_msg *msg,
    const char *domain, const char *local_addr)
{
    FILE *fp;
    char dir[PATH_MAX];
    char textfile[PATH_MAX];
    char *mbuf;
    char *subject_sf7;
    long new_textnum = 0;
    long size;
    struct passwd *pw;
    uid_t owner;
    gid_t group;

    if (uid <= 0 || msg == NULL)
        return -1;

    mbuf = build_netmail_mbuf(msg, domain, local_addr);
    if (mbuf == NULL)
        return -1;

    subject_sf7 = netmail_to_sf7_dup(
        msg->subject[0] ? msg->subject : "(no subject)", msg->chrs);
    if (subject_sf7 == NULL) {
        free(mbuf);
        return -1;
    }

    size = count_lines(mbuf);

    if (rewrite_mailbox_last_text(uid, &new_textnum) != 0) {
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    if (mailbox_dir_for_uid(uid, dir, sizeof(dir)) != 0) {
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    if (snprintf(textfile, sizeof(textfile), "%s%ld", dir, new_textnum) >= (int)sizeof(textfile)) {
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    fp = fopen(textfile, "w");
    if (fp == NULL) {
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    if (fprintf(fp, "%ld:%d:%ld:%ld:%d:%d:%ld\n",
            new_textnum, 0, (long)time(NULL), 0L, 0, 0, size) < 0) {
        fclose(fp);
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    if (fprintf(fp, "%s\n", subject_sf7) < 0) {
        fclose(fp);
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    if (fputs(mbuf, fp) == EOF) {
        fclose(fp);
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    if (fclose(fp) != 0) {
        free(subject_sf7);
        free(mbuf);
        return -1;
    }

    free(subject_sf7);
    free(mbuf);

    owner = getuid();
    group = getgid();

    pw = getpwnam(FTNNETMAIL_SKLAFF_OWNER);
    if (pw != NULL)
        owner = pw->pw_uid;

    pw = getpwuid((uid_t)uid);
    if (pw != NULL)
        group = pw->pw_gid;

    if (chmod(textfile, 0600) == -1) {
    /* Non-fatal.  The import itself succeeded. */
	}
	
	if (chown(textfile, owner, group) == -1) {
        /* Non-fatal.  The import itself succeeded. */
    }

    return 0;
}


int
send_netmail(int uid, const struct fido_msg *msg)
{
    /* Backward-compatible local helper without FTN domain context. */
    return send_netmail_with_context(uid, msg, NULL, NULL);
}

static void
notify_netmail_user(int uid, int sig)
{
    FILE *fp;
    char line[512];
    char *p;
    char *end;
    long active_uid;
    long pid;

    fp = fopen(ACTIVE_FILE, "r");
    if (fp == NULL)
        return;

    while (fgets(line, sizeof(line), fp) != NULL) {
        active_uid = strtol(line, &end, 10);
        if (end == line || *end != ':')
            continue;

        if (active_uid != uid)
            continue;

        p = end + 1;
        pid = strtol(p, &end, 10);
        if (end == p || *end != ':')
            continue;

        if (pid > 1)
            kill((pid_t)pid, sig);
    }

    fclose(fp);
}

int
import_ftn_netmail_spool_5d(const char *spooldir, const char *domain,
    const char *local_addr)
{
    DIR *dir;
    struct dirent *de;
    long seen = 0;
    long parsed = 0;
    long imported = 0;
    long skipped_nomsgid = 0;
    long skipped_unknown_user = 0;
    long skipped_duplicate = 0;
    long failed = 0;

    if (spooldir == NULL || *spooldir == '\0') {
        printf("FTN netmail import disabled: netmail spool is empty\n");
        return 0;
    }

    dir = opendir(spooldir);
    if (dir == NULL) {
        perror(spooldir);
        return -1;
    }

    printf("\n");
    printf("FTN netmail import\n");
    printf("------------------\n");
    printf("Domain:    %s\n",
        domain != NULL && *domain != '\0' ? domain : "(unknown)");
    printf("Local AKA: %s\n",
        local_addr != NULL && *local_addr != '\0' ? local_addr : "(unknown)");
    printf("Spool:     %s\n", spooldir);

    while ((de = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        struct stat st;
        struct fido_msg msg;
        int uid;

        if (!is_msg_file(de->d_name))
            continue;

        seen++;

        if (snprintf(path, sizeof(path), "%s/%s", spooldir, de->d_name) >= (int)sizeof(path)) {
            fprintf(stderr, "[ERROR] Netmail path too long: %s/%s\n", spooldir, de->d_name);
            failed++;
            continue;
        }

        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;

        memset(&msg, 0, sizeof(msg));
        if (read_fido_msg(path, &msg) != 0) {
            fprintf(stderr, "[ERROR] Could not parse netmail: %s\n", path);
            failed++;
            continue;
        }

        parsed++;

        if (msg.msgid[0] == '\0') {
            printf("[SKIP] %s has no MSGID; refusing import to avoid duplicates\n", de->d_name);
            skipped_nomsgid++;
            free_fido_msg(&msg);
            continue;
        }

        uid = find_netmail_user(msg.to);
        if (uid <= 0) {
            printf("[SKIP] %s: no local SklaffKOM user found for To: %s\n",
                de->d_name, msg.to[0] ? msg.to : "(missing)");
            skipped_unknown_user++;
            free_fido_msg(&msg);
            continue;
        }

        if (netmail_already_imported(uid, domain, msg.msgid)) {
            printf("[SKIP] %s: duplicate FTN-MSGID %s\n", de->d_name, msg.msgid);
            skipped_duplicate++;
            free_fido_msg(&msg);
            continue;
        }

        if (send_netmail_with_context(uid, &msg, domain,
                local_addr) != 0) {
            fprintf(stderr, "[ERROR] Could not import netmail %s for uid %d\n", de->d_name, uid);
            failed++;
            free_fido_msg(&msg);
            continue;
        }

        printf("[IMPORT] %s: %s -> uid %d, subject: %s\n",
            de->d_name,
            msg.from[0] ? msg.from : "(unknown)",
            uid,
            msg.subject[0] ? msg.subject : "(no subject)");

        notify_netmail_user(uid, SIGNAL_NEW_TEXT);
        imported++;

        free_fido_msg(&msg);
    }

    closedir(dir);

    printf("\n");
    printf("FTN netmail import done\n");
    printf("Seen:             %ld .MSG file(s)\n", seen);
    printf("Parsed:           %ld\n", parsed);
    printf("Imported:         %ld\n", imported);
    printf("Duplicates:       %ld skipped\n", skipped_duplicate);
    printf("Missing MSGID:    %ld skipped\n", skipped_nomsgid);
    printf("Unknown user:     %ld skipped\n", skipped_unknown_user);
    printf("Failed:           %ld\n", failed);

    return failed ? -1 : 0;
}


int
import_ftn_netmail_spool(const char *spooldir)
{
    /* Backward-compatible single-spool import without 5D metadata. */
    return import_ftn_netmail_spool_5d(spooldir, NULL, NULL);
}
