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
static int netmail_already_imported(int uid, const char *msgid);
static void ftn_msgid_origin(const char *msgid, char *out, size_t outsz);
static char *build_netmail_mbuf(const struct fido_msg *msg);
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
    int found = 0;

    if (new_textnum == NULL)
        return -1;

    if (mailbox_file_for_uid(uid, path, sizeof(path)) != 0)
        return -1;

    if (snprintf(tmpfile, sizeof(tmpfile), "%s.ftnnetmail.tmp", path) >= (int)sizeof(tmpfile))
        return -1;

    in = fopen(path, "r");
    if (in == NULL)
        return -1;

    out = fopen(tmpfile, "w");
    if (out == NULL) {
        fclose(in);
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
netmail_already_imported(int uid, const char *msgid)
{
    char dir[PATH_MAX];
    char path[PATH_MAX];
    char line[1024];
    char needle[512];
    long last_text = 0;
    long i;

    if (msgid == NULL || *msgid == '\0')
        return 0;

    if (read_mailbox_last_text(uid, &last_text) != 0)
        return 0;

    if (mailbox_dir_for_uid(uid, dir, sizeof(dir)) != 0)
        return 0;

    snprintf(needle, sizeof(needle), "FTN-MSGID: %s", msgid);

    for (i = 1; i <= last_text; i++) {
        FILE *fp;

        if (snprintf(path, sizeof(path), "%s%ld", dir, i) >= (int)sizeof(path))
            continue;

        fp = fopen(path, "r");
        if (fp == NULL)
            continue;

        while (fgets(line, sizeof(line), fp) != NULL) {
            line[strcspn(line, "\r\n")] = '\0';
            if (strcmp(line, needle) == 0) {
                fclose(fp);
                return 1;
            }
        }

        fclose(fp);
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

static char *
build_netmail_mbuf(const struct fido_msg *msg)
{
    char fromaddr[128];
    char fromline[512];
	const char *body;
    char *mbuf;
    size_t need;

    if (msg == NULL)
        return NULL;

    body = msg->clean_body;
    if (body == NULL)
        body = msg->raw_body;
    if (body == NULL)
        body = "";

    ftn_msgid_origin(msg->msgid, fromaddr, sizeof(fromaddr));

		/*
	     * Store the FTN origin address in the visible From: header too, so
	     * SklaffKOM's normal mailbox header shows where netmail came from.
	     *
	     * modified on 2026-07-09, PL
	     */
    if (fromaddr[0] != '\0') {
        snprintf(fromline, sizeof(fromline), "%s (%s)",
            msg->from[0] ? msg->from : "(unknown)", fromaddr);
    } else {
        snprintf(fromline, sizeof(fromline), "%s",
            msg->from[0] ? msg->from : "(unknown)");
    }
    need = 1024;
    need += strlen(msg->from);
    need += strlen(msg->to);
    need += strlen(msg->subject);
    need += strlen(msg->date);
    need += strlen(msg->msgid);
    need += strlen(msg->reply);
    need += strlen(msg->chrs);
    need += strlen(fromaddr);
    need += strlen(body);

    mbuf = calloc(1, need);
    if (mbuf == NULL)
        return NULL;

    snprintf(mbuf, need,
        "From: %s\n"
        "To: %s\n"
        "Subject: %s\n"
        "Date: %s\n"
        "FTN-Netmail: yes\n",
        fromline,
        msg->to,
        msg->subject,
        msg->date);

    if (fromaddr[0] != '\0') {
        strlcat(mbuf, "FTN-FromAddr: ", need);
        strlcat(mbuf, fromaddr, need);
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
    strlcat(mbuf, body, need);

    return mbuf;
}

int
send_netmail(int uid, const struct fido_msg *msg)
{
    FILE *fp;
    char dir[PATH_MAX];
    char textfile[PATH_MAX];
    char *mbuf;
    long new_textnum = 0;
    long size;
    struct passwd *pw;
    uid_t owner;
    gid_t group;

    if (uid <= 0 || msg == NULL)
        return -1;

    mbuf = build_netmail_mbuf(msg);
    if (mbuf == NULL)
        return -1;

    size = count_lines(mbuf);

    if (rewrite_mailbox_last_text(uid, &new_textnum) != 0) {
        free(mbuf);
        return -1;
    }

    if (mailbox_dir_for_uid(uid, dir, sizeof(dir)) != 0) {
        free(mbuf);
        return -1;
    }

    if (snprintf(textfile, sizeof(textfile), "%s%ld", dir, new_textnum) >= (int)sizeof(textfile)) {
        free(mbuf);
        return -1;
    }

    fp = fopen(textfile, "w");
    if (fp == NULL) {
        free(mbuf);
        return -1;
    }

    if (fprintf(fp, "%ld:%d:%ld:%ld:%d:%d:%ld\n",
            new_textnum, 0, (long)time(NULL), 0L, 0, 0, size) < 0) {
        fclose(fp);
        free(mbuf);
        return -1;
    }

    if (fprintf(fp, "%s\n", msg->subject[0] ? msg->subject : "(no subject)") < 0) {
        fclose(fp);
        free(mbuf);
        return -1;
    }

    if (fputs(mbuf, fp) == EOF) {
        fclose(fp);
        free(mbuf);
        return -1;
    }

    if (fclose(fp) != 0) {
        free(mbuf);
        return -1;
    }

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
import_ftn_netmail_spool(const char *spooldir)
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
        printf("FTN netmail import disabled: FTN_NETMAIL_SPOOL is empty\n");
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
    printf("Spool: %s\n", spooldir);

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

        if (netmail_already_imported(uid, msg.msgid)) {
            printf("[SKIP] %s: duplicate FTN-MSGID %s\n", de->d_name, msg.msgid);
            skipped_duplicate++;
            free_fido_msg(&msg);
            continue;
        }

        if (send_netmail(uid, &msg) != 0) {
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
