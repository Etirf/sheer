#include "cmd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * caveat: we only know the string, not the actual filesystem. /tmp/foo
 * could be a symlink to /etc/shadow and we'd happily say "LOW". not our
 * problem. if you're being socially-engineered via path names, sheer is
 * not your biggest issue.
 */
static Risk path_risk(const char *path)
{
    if (!path || path[0] == '\0')
        return RISK_SAFE;

    if (strcmp(path, "/")   == 0 ||
        strcmp(path, "/*")  == 0 ||
        strcmp(path, "/.")  == 0)
        return RISK_CRITICAL;

    static const char *const sys_dirs[] = {
        "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32",
        "/lib64", "/libx32", "/proc", "/root", "/run",
        "/sbin", "/srv", "/sys", "/usr", "/var", "/home",
        NULL
    };
    for (int i = 0; sys_dirs[i]; i++) {
        size_t len = strlen(sys_dirs[i]);
        if (strncmp(path, sys_dirs[i], len) == 0 &&
            (path[len] == '\0' || path[len] == '/' || path[len] == '*'))
            return RISK_HIGH;
    }

    if (strchr(path, '*') || strchr(path, '?'))
        return RISK_MEDIUM;  /* wildcards are spicy */

    if (strncmp(path, "/tmp", 4) == 0)
        return RISK_LOW;

    return RISK_SAFE;
}

static const char *sig_desc(int sig)
{
    switch (sig) {
    case  1: return "SIGHUP (hangup / reload)";
    case  2: return "SIGINT (interrupt, like Ctrl-C)";
    case  3: return "SIGQUIT (quit with core dump)";
    case  6: return "SIGABRT (abort)";
    case  9: return "SIGKILL (force-kill, unblockable)";
    case 11: return "SIGSEGV (segmentation fault)";
    case 15: return "SIGTERM (graceful termination)";
    case 17: return "SIGCHLD (child status changed)";
    case 18: return "SIGCONT (resume)";
    case 19: return "SIGSTOP (pause, unblockable)";
    default: return "a signal";
    }
}

static void chmod_octal_desc(const char *mode_str, char *buf, size_t len)
{
    char *end;
    long m = strtol(mode_str, &end, 8);
    if (end == mode_str || *end != '\0') {
        snprintf(buf, len, "permissions %s", mode_str);
        return;
    }

    static const char *const rwx[8] = {
        "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"
    };
    int o = (int)((m >> 6) & 7);
    int g = (int)((m >> 3) & 7);
    int ot = (int)(m & 7);

    if (m == 0777)
        snprintf(buf, len, "full read/write/execute for all users (777)");
    else if (m == 0755)
        snprintf(buf, len, "owner rwx, group/others r-x (755)");
    else if (m == 0644)
        snprintf(buf, len, "owner rw-, others r-- (644)");
    else if (m == 0600)
        snprintf(buf, len, "owner rw- only, no access for others (600)");
    else if (m == 0400)
        snprintf(buf, len, "owner read-only, no access for others (400)");
    else
        snprintf(buf, len, "owner: %s, group: %s, others: %s (%s)",
                 rwx[o], rwx[g], rwx[ot], mode_str);
}

static void analyze_rm(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'r') || tok_has_short(tl, 'R') ||
                     tok_has_long(tl, "--recursive");
    bool force     = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool inter     = tok_has_short(tl, 'i') || tok_has_short(tl, 'I') ||
                     tok_has_long(tl, "--interactive");

    char target[256] = "(unspecified)";
    Risk path_r = RISK_SAFE;
    int  nargs  = 0;

    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type != TT_WORD) continue;
        if (nargs == 0) snprintf(target, sizeof target, "%s", t->s);
        path_r = risk_max(path_r, path_risk(t->s));
        nargs++;
    }
    if (nargs > 1)
        snprintf(target, sizeof target, "%d paths", nargs);

    if (recursive && force)
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes '%s' and everything inside it, no questions asked.", target);
    else if (recursive)
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes '%s' and everything inside it.", target);
    else if (force)
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes file '%s' without prompting, ignores missing files.", target);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes file '%s'.", target);

    out->risk = RISK_LOW;
    if (recursive) out->risk = risk_max(out->risk, RISK_MEDIUM);
    if (force)     out->risk = risk_max(out->risk, RISK_MEDIUM);
    if (recursive && force && !inter) out->risk = risk_max(out->risk, RISK_HIGH);
    out->risk = risk_max(out->risk, path_r);

    if (path_r == RISK_CRITICAL)
        snprintf(out->warning, sizeof out->warning,
                 "Targeting a critical system path - this will destroy the OS.");
    else if (out->risk >= RISK_HIGH)
        snprintf(out->warning, sizeof out->warning,
                 "Deletion is irreversible. Files cannot be recovered.");

    if (force && !inter && recursive)
        snprintf(out->safer, sizeof out->safer,
                 "rm -ri %s  (prompts before each deletion)", target);
}

static void analyze_mv(const TokList *tl, Analysis *out)
{
    bool force     = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool no_clob   = tok_has_short(tl, 'n') || tok_has_long(tl, "--no-clobber");

    char src[256] = "(source)", dst[256] = "(destination)";
    int nargs = 0;
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type != TT_WORD) continue;
        if      (nargs == 0) snprintf(src, sizeof src, "%s", t->s);
        else if (nargs == 1) snprintf(dst, sizeof dst, "%s", t->s);
        nargs++;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Moves %s to %s%s.",
             src, dst,
             force ? " (overwrites destination without prompt)" : "");

    out->risk = RISK_LOW;
    if (force && !no_clob) out->risk = risk_max(out->risk, RISK_MEDIUM);
    out->risk = risk_max(out->risk, path_risk(dst));

    if (path_risk(dst) >= RISK_HIGH)
        snprintf(out->warning, sizeof out->warning,
                 "Destination is in a system-critical path.");
}

static void analyze_cp(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'r') || tok_has_short(tl, 'R') ||
                     tok_has_long(tl, "--recursive");
    bool force     = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool no_clob   = tok_has_short(tl, 'n') || tok_has_long(tl, "--no-clobber");

    char src[256] = "(source)", dst[256] = "(destination)";
    int nargs = 0;
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type != TT_WORD) continue;
        if      (nargs == 0) snprintf(src, sizeof src, "%s", t->s);
        else if (nargs == 1) snprintf(dst, sizeof dst, "%s", t->s);
        nargs++;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Copies %s to %s%s%s.",
             src, dst,
             recursive ? " recursively" : "",
             (force && !no_clob) ? " (overwrites existing files)" : "");

    out->risk = RISK_SAFE;
    if (force && !no_clob) out->risk = risk_max(out->risk, RISK_LOW);
    out->risk = risk_max(out->risk, path_risk(dst));
}

static void analyze_chmod(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'R') || tok_has_long(tl, "--recursive");

    const Tok *mode_tok = tok_first_word(tl, 1);
    const Tok *path_tok = mode_tok
        ? tok_first_word(tl, (int)(mode_tok - tl->t) + 1)
        : NULL;

    char mode_desc[128] = "permissions";
    if (mode_tok) chmod_octal_desc(mode_tok->s, mode_desc, sizeof mode_desc);

    char target[256] = "the specified path";
    Risk path_r = RISK_SAFE;
    if (path_tok) {
        snprintf(target, sizeof target, "%s", path_tok->s);
        path_r = path_risk(path_tok->s);
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Sets %s on %s%s.",
             mode_desc, target,
             recursive ? " and all its contents" : "");

    out->risk = RISK_LOW;

    if (mode_tok) {
        char *end;
        long m = strtol(mode_tok->s, &end, 8);
        if (end != mode_tok->s && *end == '\0') {
            /* world-writable or world-executable on sensitive paths */
            if ((m & 0002) || m == 0777) {
                out->risk = risk_max(out->risk, RISK_HIGH);
                snprintf(out->warning, sizeof out->warning,
                         "World-writable permissions are a serious security risk.");
                snprintf(out->safer, sizeof out->safer,
                         "chmod 755 %s  (owner full, others read/execute)", target);
            }
        }
    }

    out->risk = risk_max(out->risk, path_r);
    if (recursive) out->risk = risk_max(out->risk, RISK_MEDIUM);
}

static void analyze_chown(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'R') || tok_has_long(tl, "--recursive");

    const Tok *owner_tok = tok_first_word(tl, 1);
    const Tok *path_tok  = owner_tok
        ? tok_first_word(tl, (int)(owner_tok - tl->t) + 1)
        : NULL;

    char target[256] = "the specified path";
    Risk path_r = RISK_SAFE;
    if (path_tok) {
        snprintf(target, sizeof target, "%s", path_tok->s);
        path_r = path_risk(path_tok->s);
    }

    char owner[64] = "a new owner";
    if (owner_tok) snprintf(owner, sizeof owner, "%s", owner_tok->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Changes ownership of %s to %s%s.",
             target, owner, recursive ? " recursively" : "");

    out->risk = RISK_LOW;
    out->risk = risk_max(out->risk, path_r);
    if (recursive) out->risk = risk_max(out->risk, RISK_MEDIUM);
    if (owner_tok &&
        (strcmp(owner_tok->s, "root") == 0 || strcmp(owner_tok->s, "root:root") == 0))
        out->risk = risk_max(out->risk, RISK_HIGH);
}

static void analyze_ln(const TokList *tl, Analysis *out)
{
    bool symbolic = tok_has_short(tl, 's') || tok_has_long(tl, "--symbolic");
    bool force    = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");

    char tgt[256]  = "(target)";
    char link[256] = "(link name)";
    int nargs = 0;
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type != TT_WORD) continue;
        if      (nargs == 0) snprintf(tgt,  sizeof tgt,  "%s", t->s);
        else if (nargs == 1) snprintf(link, sizeof link, "%s", t->s);
        nargs++;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Creates a %s link at %s pointing to %s%s.",
             symbolic ? "symbolic" : "hard", link, tgt,
             force ? " (overwrites existing)" : "");

    out->risk = force ? RISK_LOW : RISK_SAFE;
}

static void analyze_find(const TokList *tl, Analysis *out)
{
    bool has_delete = false;
    bool has_exec   = false;
    bool exec_rm    = false;

    /*
     * NOTE: we now split pipelines in main.c before reaching here, so when
     * we see "find /var/log -name '*.log'", the "| xargs rm" part is gone.
     * sheer scores each stage independently and aggregates at the end.
     * so this function only sees one stage at a time now - good.
     */
    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (strcmp(s, "-delete") == 0) { has_delete = true; continue; }
        if (strcmp(s, "-exec") == 0 || strcmp(s, "-execdir") == 0) {
            has_exec = true;
            if (i + 1 < tl->n) {
                const char *cmd = tl->t[i + 1].s;
                /* strip path prefix */
                const char *sl = strrchr(cmd, '/');
                if (sl) cmd = sl + 1;
                if (strcmp(cmd, "rm") == 0 || strcmp(cmd, "shred") == 0)
                    exec_rm = true;
            }
        }
    }

    /* Search root: first WORD after the command */
    const Tok *root = tok_first_word(tl, 1);
    char root_desc[256] = "the current directory";
    Risk path_r = RISK_SAFE;
    if (root) {
        snprintf(root_desc, sizeof root_desc, "%s", root->s);
        path_r = path_risk(root->s);
    }

    /* Name pattern */
    char name_desc[128] = "files";
    for (int i = 1; i < tl->n - 1; i++) {
        if (strcmp(tl->t[i].s, "-name") == 0 ||
            strcmp(tl->t[i].s, "-iname") == 0) {
            snprintf(name_desc, sizeof name_desc,
                     "files matching '%s'", tl->t[i + 1].s);
            break;
        }
    }

    if (has_delete || exec_rm) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Finds and permanently deletes %s under %s.",
                 name_desc, root_desc);
        out->risk = risk_max(RISK_HIGH, path_r);
        snprintf(out->warning, sizeof out->warning,
                 "Deletion via find is irreversible.");
        snprintf(out->safer, sizeof out->safer,
                 "Replace -delete with -print first to preview matches.");
    } else if (has_exec) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Finds %s under %s and executes a command on each match.",
                 name_desc, root_desc);
        out->risk = risk_max(RISK_MEDIUM, path_r);
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Searches for %s under %s.", name_desc, root_desc);
        /* read-only search. cap at MEDIUM even for /etc: it's just traversal,
         * not modification. HIGH would be alarmist and annoying. */
        Risk cap = path_r > RISK_MEDIUM ? RISK_MEDIUM : path_r;
        out->risk = cap;
    }
}

static void analyze_tar(const TokList *tl, Analysis *out)
{
    bool create   = tok_has_short(tl, 'c');
    bool extract  = tok_has_short(tl, 'x');
    bool list     = tok_has_short(tl, 't');
    bool gzip     = tok_has_short(tl, 'z');
    bool bzip2    = tok_has_short(tl, 'j');
    bool xz       = tok_has_short(tl, 'J');
    bool keep_old = tok_has_short(tl, 'k') || tok_has_long(tl, "--keep-old-files");

    const char *archive = tok_short_val(tl, 'f');
    if (!archive) archive = tok_long_val(tl, "--file");

    char comp[32] = "";
    if (gzip)  snprintf(comp, sizeof comp, "gzip-compressed ");
    if (bzip2) snprintf(comp, sizeof comp, "bzip2-compressed ");
    if (xz)    snprintf(comp, sizeof comp, "xz-compressed ");

    char arc_desc[256] = "an archive";
    if (archive) snprintf(arc_desc, sizeof arc_desc, "%s%s", comp, archive);

    if (create) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Creates %s.", arc_desc);
        out->risk = RISK_LOW;
    } else if (extract) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Extracts %s%s.",
                 arc_desc,
                 keep_old ? " (skips existing files)" : " (may overwrite existing files)");
        out->risk = RISK_LOW;
        if (!keep_old)
            snprintf(out->safer, sizeof out->safer,
                     "Add -k to preserve existing files, or tar -tf %s to preview.",
                     archive ? archive : "archive");
    } else if (list) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists contents of %s.", arc_desc);
        out->risk = RISK_SAFE;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Operates on archive %s.", arc_desc);
        out->risk = RISK_LOW;
    }
}

static void analyze_kill(const TokList *tl, Analysis *out)
{
    int sig = 15; /* default SIGTERM */

    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type != TT_FLAG_SHORT) continue;
        const char *s = t->s + 1;
        if (*s >= '0' && *s <= '9') { sig = atoi(s); break; }
        /* -SIGKILL, -TERM etc. - leave at default for brevity */
    }

    char pid_desc[128] = "the specified process";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(pid_desc, sizeof pid_desc, "PID %s", tl->t[i].s);
            break;
        }
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Sends %s to %s.", sig_desc(sig), pid_desc);

    out->risk = (sig == 9 || sig == 19) ? RISK_HIGH : RISK_MEDIUM;
    if (sig == 9)
        snprintf(out->warning, sizeof out->warning,
                 "SIGKILL cannot be caught or ignored - the process dies immediately "
                 "without any cleanup.");
}

static void analyze_pkill(const TokList *tl, Analysis *out)
{
    int sig = 15;
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type == TT_FLAG_SHORT) {
            const char *s = t->s + 1;
            if (*s >= '0' && *s <= '9') { sig = atoi(s); break; }
        }
    }

    char pattern[128] = "(pattern)";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(pattern, sizeof pattern, "%s", tl->t[i].s);
            break;
        }
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Sends %s to all processes whose name matches '%s'.",
             sig_desc(sig), pattern);

    out->risk = (sig == 9) ? RISK_HIGH : RISK_MEDIUM;
    if (sig == 9)
        snprintf(out->warning, sizeof out->warning,
                 "SIGKILL cannot be caught - all matched processes die immediately.");
}

static void analyze_killall(const TokList *tl, Analysis *out)
{
    int sig = 15;
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type == TT_FLAG_SHORT) {
            const char *s = t->s + 1;
            if (*s >= '0' && *s <= '9') { sig = atoi(s); break; }
        }
    }

    char name[128] = "(name)";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(name, sizeof name, "%s", tl->t[i].s);
            break;
        }
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Sends %s to all processes named '%s'.", sig_desc(sig), name);

    out->risk = (sig == 9) ? RISK_HIGH : RISK_MEDIUM;
    if (sig == 9)
        snprintf(out->warning, sizeof out->warning,
                 "SIGKILL cannot be caught - all matched processes die immediately.");
}

static void analyze_dd(const TokList *tl, Analysis *out)
{
    const char *inf  = NULL;
    const char *outf = NULL;

    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (strncmp(s, "if=", 3) == 0) inf  = s + 3;
        if (strncmp(s, "of=", 3) == 0) outf = s + 3;
    }

    char src[256] = "input";
    char dst[256] = "output";
    if (inf)  snprintf(src, sizeof src, "%s", inf);
    if (outf) snprintf(dst, sizeof dst, "%s", outf);

    bool to_dev   = outf && strncmp(outf, "/dev/", 5) == 0;
    bool from_zero = inf && strcmp(inf, "/dev/zero") == 0;
    bool from_rnd  = inf && (strcmp(inf, "/dev/urandom") == 0 ||
                              strcmp(inf, "/dev/random")  == 0);

    if (to_dev && (from_zero || from_rnd)) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Overwrites device %s with %s - effectively wiping it.",
                 dst, from_rnd ? "random data (secure erase)" : "zeros");
        out->risk = RISK_CRITICAL;
        snprintf(out->warning, sizeof out->warning,
                 "ALL data on %s will be permanently and unrecoverably destroyed.", dst);
    } else if (to_dev) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Writes raw data from %s directly to device %s.", src, dst);
        out->risk = RISK_CRITICAL;
        snprintf(out->warning, sizeof out->warning,
                 "Writing directly to a block device bypasses the filesystem - "
                 "typically irreversible.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Copies raw data from %s to %s.", src, dst);
        out->risk = RISK_MEDIUM;
        out->risk = risk_max(out->risk, path_risk(dst));
    }
}

static void analyze_mkfs(const TokList *tl, Analysis *out)
{
    const char *cmd = tl->n > 0 ? tl->t[0].s : "mkfs";
    const char *dot = strchr(cmd, '.');

    char fstype[32] = "a new filesystem";
    if (dot) snprintf(fstype, sizeof fstype, "%s filesystem", dot + 1);

    const Tok *dev = tok_first_word(tl, 1);
    char dev_desc[256] = "the specified device";
    if (dev) snprintf(dev_desc, sizeof dev_desc, "%s", dev->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Formats %s as %s, erasing all existing data.",
             dev_desc, fstype);

    out->risk = RISK_CRITICAL;
    snprintf(out->warning, sizeof out->warning,
             "ALL data on %s will be permanently destroyed. This cannot be undone.",
             dev_desc);
}

static void analyze_git_reset(const TokList *tl, Analysis *out)
{
    bool hard  = tok_has_long(tl, "--hard");
    bool soft  = tok_has_long(tl, "--soft");

    char ref[128] = "the current HEAD";
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type == TT_WORD && strcmp(t->s, "reset") != 0) {
            snprintf(ref, sizeof ref, "%s", t->s);
            break;
        }
    }

    if (hard) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Moves HEAD to %s and discards ALL uncommitted changes "
                 "(staged and unstaged).", ref);
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "Unstaged and staged changes are permanently lost.");
        snprintf(out->safer, sizeof out->safer,
                 "git stash  (preserve changes before resetting)");
    } else if (soft) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Moves HEAD to %s, keeping all changes staged for commit.", ref);
        out->risk = RISK_LOW;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Moves HEAD to %s, unstaging changes while keeping them "
                 "in the working tree (default --mixed).", ref);
        out->risk = RISK_LOW;
    }
}

static void analyze_git_clean(const TokList *tl, Analysis *out)
{
    bool force   = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool dirs    = tok_has_short(tl, 'd');
    bool dry_run = tok_has_short(tl, 'n') || tok_has_long(tl, "--dry-run");
    bool ignored = tok_has_short(tl, 'x');
    bool only_ig = tok_has_short(tl, 'X');

    if (dry_run) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows what would be removed (dry run - nothing is deleted).");
        out->risk = RISK_SAFE;
        return;
    }
    if (!force) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Would remove untracked files, but -f is required to execute.");
        out->risk = RISK_SAFE;
        return;
    }

    char what[256] = "untracked files";
    if (dirs && ignored)
        snprintf(what, sizeof what,
                 "untracked files, directories, and .gitignore-ignored files");
    else if (dirs)
        snprintf(what, sizeof what, "untracked files and directories");
    else if (ignored)
        snprintf(what, sizeof what,
                 "untracked files plus files ignored by .gitignore");
    else if (only_ig)
        snprintf(what, sizeof what, "files ignored by .gitignore only");

    snprintf(out->explanation, sizeof out->explanation,
             "Permanently removes %s from the working tree.", what);
    out->risk = RISK_HIGH;
    snprintf(out->warning, sizeof out->warning,
             "Removed files are untracked - git cannot recover them.");
    snprintf(out->safer, sizeof out->safer,
             "git clean -n  (preview what would be removed)");
}

static void analyze_git_checkout(const TokList *tl, Analysis *out)
{
    bool force      = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool new_branch = tok_has_short(tl, 'b') || tok_has_short(tl, 'B');

    char tgt[256] = "the specified branch or file";
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type == TT_WORD && strcmp(t->s, "checkout") != 0) {
            snprintf(tgt, sizeof tgt, "%s", t->s);
            break;
        }
    }

    if (new_branch) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Creates and switches to new branch '%s'.", tgt);
        out->risk = RISK_SAFE;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Switches to %s%s.", tgt,
                 force ? " (discarding uncommitted changes)" : "");
        out->risk = force ? RISK_HIGH : RISK_LOW;
        if (force)
            snprintf(out->warning, sizeof out->warning,
                     "Uncommitted changes to checked-out files will be overwritten.");
    }
}

static void analyze_git_push(const TokList *tl, Analysis *out)
{
    bool force    = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool force_wl = tok_has_long(tl, "--force-with-lease");
    bool del      = tok_has_short(tl, 'd') || tok_has_long(tl, "--delete");
    bool tags     = tok_has_long(tl, "--tags");

    /* Skip subcommand word ("push") to reach arguments */
    const Tok *subcmd = tok_first_word(tl, 1);
    const Tok *remote = subcmd ? tok_first_word(tl, (int)(subcmd - tl->t) + 1) : NULL;
    const Tok *branch = remote ? tok_first_word(tl, (int)(remote - tl->t) + 1) : NULL;

    char remote_s[64] = "remote";
    char branch_s[64] = "current branch";
    if (remote) snprintf(remote_s, sizeof remote_s, "%s", remote->s);
    if (branch) snprintf(branch_s, sizeof branch_s, "%s", branch->s);

    if (del) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes branch '%s' from %s.", branch_s, remote_s);
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "Remote branch deletion affects all collaborators.");
    } else if (force && !force_wl) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Force-pushes %s to %s, rewriting remote history.",
                 branch_s, remote_s);
        out->risk = RISK_CRITICAL;
        snprintf(out->warning, sizeof out->warning,
                 "Rewrites remote history. All collaborators must re-sync "
                 "(git pull --rebase or re-clone).");
        snprintf(out->safer, sizeof out->safer,
                 "git push --force-with-lease  (aborts if remote changed)");
    } else if (force_wl) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Force-pushes %s to %s only if no one else has pushed since "
                 "your last fetch.",
                 branch_s, remote_s);
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Still rewrites history, but guards against clobbering others' work.");
    } else if (tags) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Pushes %s and all local tags to %s.", branch_s, remote_s);
        out->risk = RISK_LOW;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Pushes %s to %s.", branch_s, remote_s);
        out->risk = RISK_SAFE;
    }
}

static void analyze_docker_run(const TokList *tl, Analysis *out)
{
    bool privileged = tok_has_long(tl, "--privileged");
    bool remove     = tok_has_long(tl, "--rm");
    bool detached   = tok_has_short(tl, 'd');
    bool net_host   = false;

    const char *netval = tok_long_val(tl, "--network");
    if (netval && strcmp(netval, "host") == 0) net_host = true;

    const char *name = tok_long_val(tl, "--name");

    const char *ports[8], *vols[8];
    int n_ports = 0, n_vols = 0;

    for (int i = 1; i < tl->n - 1; i++) {
        if (tl->t[i].type != TT_FLAG_SHORT) continue;
        size_t slen = strlen(tl->t[i].s);
        if (slen < 2) continue;
        char last = tl->t[i].s[slen - 1];
        if (last == 'p' && n_ports < 8)
            ports[n_ports++] = tl->t[i + 1].s;
        if (last == 'v' && n_vols < 8)
            vols[n_vols++] = tl->t[i + 1].s;
    }

    const char *other_vals[] = {
        tok_short_val(tl, 'e'),
        tok_short_val(tl, 'u'),
        tok_long_val(tl, "--network"),
        tok_long_val(tl, "--entrypoint"),
        tok_long_val(tl, "--hostname"),
        name,
    };

    const char *image = NULL;
    bool found_run = false;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type != TT_WORD) continue;
        if (!found_run) { found_run = true; continue; }
        const char *s = tl->t[i].s;
        bool is_val = false;
        for (int k = 0; k < n_ports && !is_val; k++)
            if (strcmp(s, ports[k]) == 0) is_val = true;
        for (int k = 0; k < n_vols && !is_val; k++)
            if (strcmp(s, vols[k]) == 0) is_val = true;
        for (size_t k = 0; k < sizeof other_vals / sizeof other_vals[0] && !is_val; k++)
            if (other_vals[k] && strcmp(s, other_vals[k]) == 0) is_val = true;
        if (!is_val) { image = s; break; }
    }

    int off = 0;
    if (image)
        off = snprintf(out->explanation, sizeof out->explanation,
                       "Runs a Docker container from image '%s'", image);
    else
        off = snprintf(out->explanation, sizeof out->explanation,
                       "Runs a Docker container");
    if (off < 0) off = 0;

    if (name && off < (int)sizeof out->explanation)
        off += snprintf(out->explanation + off, sizeof out->explanation - (size_t)off,
                        ", named '%s'", name);
    for (int i = 0; i < n_ports && off < (int)sizeof out->explanation; i++)
        off += snprintf(out->explanation + off, sizeof out->explanation - (size_t)off,
                        ", port %s exposed", ports[i]);
    for (int i = 0; i < n_vols && off < (int)sizeof out->explanation; i++)
        off += snprintf(out->explanation + off, sizeof out->explanation - (size_t)off,
                        ", volume %s mounted", vols[i]);
    if (detached && off < (int)sizeof out->explanation)
        off += snprintf(out->explanation + off, sizeof out->explanation - (size_t)off,
                        ", in background");
    if (remove && off < (int)sizeof out->explanation)
        off += snprintf(out->explanation + off, sizeof out->explanation - (size_t)off,
                        ", auto-removed on exit");
    if (off < (int)sizeof out->explanation)
        snprintf(out->explanation + off, sizeof out->explanation - (size_t)off, ".");

    out->risk = RISK_LOW;
    if (privileged) {
        out->risk = RISK_CRITICAL;
        snprintf(out->warning, sizeof out->warning,
                 "--privileged grants the container full host kernel access "
                 "(equivalent to running as root on the host).");
    } else if (net_host) {
        out->risk = risk_max(out->risk, RISK_HIGH);
        snprintf(out->warning, sizeof out->warning,
                 "--network host removes container network isolation.");
    }
    for (int i = 0; i < n_vols; i++) {
        char host_path[256];
        snprintf(host_path, sizeof host_path, "%s", vols[i]);
        char *colon = strchr(host_path, ':');
        if (colon) *colon = '\0';
        if (path_risk(host_path) >= RISK_HIGH)
            out->risk = risk_max(out->risk, RISK_HIGH);
    }
}

static void analyze_docker_rm(const TokList *tl, Analysis *out)
{
    bool force   = tok_has_short(tl, 'f') || tok_has_long(tl, "--force");
    bool volumes = tok_has_short(tl, 'v') || tok_has_long(tl, "--volumes");

    char ct[128] = "the specified container";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD && strcmp(tl->t[i].s, "rm") != 0) {
            snprintf(ct, sizeof ct, "container '%s'", tl->t[i].s);
            break;
        }
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Removes %s%s%s.",
             ct,
             force   ? " (kills if still running)" : "",
             volumes ? " and its associated volumes" : "");

    out->risk = force ? RISK_HIGH : RISK_MEDIUM;
    if (volumes)
        snprintf(out->warning, sizeof out->warning,
                 "Volume data will be permanently deleted.");
}

static void analyze_docker_exec(const TokList *tl, Analysis *out)
{
    bool interactive = tok_has_short(tl, 'i') || tok_has_short(tl, 't');
    const char *user = tok_long_val(tl, "--user");
    if (!user) user  = tok_short_val(tl, 'u');
    bool as_root = user && (strcmp(user, "root") == 0 || strcmp(user, "0") == 0);

    char ct[128]  = "the container";
    char cmd[128] = "a command";
    int  wc = 0;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type != TT_WORD || strcmp(tl->t[i].s, "exec") == 0) continue;
        if      (wc == 0) snprintf(ct,  sizeof ct,  "container '%s'", tl->t[i].s);
        else if (wc == 1) snprintf(cmd, sizeof cmd, "'%s'",            tl->t[i].s);
        wc++;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Executes %s inside %s%s%s.",
             cmd, ct,
             interactive ? " interactively" : "",
             as_root     ? " as root"       : "");

    out->risk = interactive ? RISK_MEDIUM : RISK_LOW;
    if (as_root) out->risk = risk_max(out->risk, RISK_HIGH);
}

static void analyze_curl(const TokList *tl, Analysis *out)
{
    const char *method = tok_short_val(tl, 'X');
    if (!method) method = tok_long_val(tl, "--request");
    bool output = tok_has_short(tl, 'o') || tok_has_short(tl, 'O');
    bool silent = tok_has_short(tl, 's') || tok_has_long(tl, "--silent");
    bool data   = tok_has_short(tl, 'd') || tok_has_long(tl, "--data") ||
                  tok_has_long(tl, "--data-raw");

    char url[256] = "a URL";
    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0) {
            snprintf(url, sizeof url, "%s", s);
            break;
        }
    }

    char m[16] = "GET";
    if (method) snprintf(m, sizeof m, "%s", method);
    else if (data) snprintf(m, sizeof m, "POST");

    snprintf(out->explanation, sizeof out->explanation,
             "Sends an HTTP %s request to %s%s%s.",
             m, url,
             output ? ", saving the response to a file" : "",
             silent ? " (silent mode)" : "");

    out->risk = RISK_SAFE;
    if (strcmp(m, "DELETE") == 0) out->risk = RISK_HIGH;
    else if (strcmp(m, "POST") == 0 || strcmp(m, "PUT") == 0 ||
             strcmp(m, "PATCH") == 0) out->risk = RISK_MEDIUM;
}

static void analyze_wget(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'r') || tok_has_long(tl, "--recursive");
    const char *outfile = tok_short_val(tl, 'O');
    if (!outfile) outfile = tok_long_val(tl, "--output-document");

    char url[256] = "a URL";
    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0) {
            snprintf(url, sizeof url, "%s", s);
            break;
        }
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Downloads %s%s%s.",
             url,
             recursive ? " and all linked resources" : "",
             outfile   ? " to a specified file"       : "");

    out->risk = RISK_LOW;
    /* Piping to shell (wget -O - | sh) is dangerous but we can't detect
     * the pipe here - it would appear as a separate process */
}

static void analyze_rsync(const TokList *tl, Analysis *out)
{
    bool del     = tok_has_long(tl, "--delete") ||
                   tok_has_long(tl, "--delete-after") ||
                   tok_has_long(tl, "--delete-before");
    bool archive = tok_has_short(tl, 'a') || tok_has_long(tl, "--archive");
    bool dry_run = tok_has_short(tl, 'n') || tok_has_long(tl, "--dry-run");

    char src[256] = "source", dst[256] = "destination";
    int nargs = 0;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type != TT_WORD) continue;
        if      (nargs == 0) snprintf(src, sizeof src, "%s", tl->t[i].s);
        else if (nargs == 1) snprintf(dst, sizeof dst, "%s", tl->t[i].s);
        nargs++;
    }

    if (dry_run) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Dry run: shows what would sync from %s to %s (nothing changed).",
                 src, dst);
        out->risk = RISK_SAFE;
        return;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Syncs %s to %s%s%s.",
             src, dst,
             archive ? " (preserving permissions, timestamps, symlinks)" : "",
             del     ? ", deleting destination files absent at source" : "");

    out->risk = RISK_LOW;
    if (del) {
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "--delete permanently removes files at destination that are "
                 "not present at source.");
        snprintf(out->safer, sizeof out->safer,
                 "rsync -n ...  (dry run to preview before deleting)");
    }
    out->risk = risk_max(out->risk, path_risk(dst));
}

static void analyze_scp(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'r') || tok_has_short(tl, 'R');

    char src[256] = "source", dst[256] = "destination";
    int nargs = 0;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type != TT_WORD) continue;
        if      (nargs == 0) snprintf(src, sizeof src, "%s", tl->t[i].s);
        else if (nargs == 1) snprintf(dst, sizeof dst, "%s", tl->t[i].s);
        nargs++;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Copies %s to %s over SSH%s.",
             src, dst, recursive ? " recursively" : "");

    out->risk = RISK_LOW;
    out->risk = risk_max(out->risk, path_risk(dst));
}

static void analyze_iptables(const TokList *tl, Analysis *out)
{
    bool flush  = tok_has_short(tl, 'F') || tok_has_long(tl, "--flush");
    bool append = tok_has_short(tl, 'A') || tok_has_long(tl, "--append");
    bool del    = tok_has_short(tl, 'D') || tok_has_long(tl, "--delete");
    bool insert = tok_has_short(tl, 'I') || tok_has_long(tl, "--insert");
    bool policy = tok_has_short(tl, 'P') || tok_has_long(tl, "--policy");

    const char *chain  = NULL;
    const char *action = NULL;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            if      (!chain)  chain  = tl->t[i].s;
            else if (!action) action = tl->t[i].s;
            else break;
        }
    }
    const char *target = tok_short_val(tl, 'j');
    if (!target) target = tok_long_val(tl, "--jump");

    if (flush) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Flushes (clears) all rules from %s.",
                 chain ? chain : "all chains");
        out->risk = RISK_CRITICAL;
        snprintf(out->warning, sizeof out->warning,
                 "Clearing firewall rules may immediately expose services "
                 "to the network.");
    } else if (policy) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Sets the default policy for chain %s to %s.",
                 chain ? chain : "?", action ? action : "?");
        out->risk = RISK_HIGH;
        if (action && strcmp(action, "ACCEPT") == 0)
            snprintf(out->warning, sizeof out->warning,
                     "Setting a chain default policy to ACCEPT is permissive - "
                     "all unmatched packets are allowed.");
    } else if (append || insert) {
        const char *action_desc = "";
        if (target) {
            if      (strcmp(target, "DROP")   == 0) action_desc = " (silently drops matching traffic)";
            else if (strcmp(target, "ACCEPT") == 0) action_desc = " (accepts matching traffic)";
            else if (strcmp(target, "REJECT") == 0) action_desc = " (rejects with an error response)";
        }
        snprintf(out->explanation, sizeof out->explanation,
                 "%s a rule to chain %s%s.",
                 append ? "Appends" : "Inserts",
                 chain ? chain : "?",
                 action_desc);
        out->risk = RISK_MEDIUM;
    } else if (del) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes a rule from chain %s.", chain ? chain : "?");
        out->risk = RISK_MEDIUM;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Modifies netfilter firewall rules.");
        out->risk = RISK_MEDIUM;
    }
}

static void analyze_systemctl(const TokList *tl, Analysis *out)
{
    const Tok *subcmd = tok_first_word(tl, 1);
    const Tok *unit   = subcmd
        ? tok_first_word(tl, (int)(subcmd - tl->t) + 1)
        : NULL;

    char sub[64]  = "unknown";
    char svc[128] = "the specified unit";
    if (subcmd) snprintf(sub, sizeof sub, "%s", subcmd->s);
    if (unit)   snprintf(svc, sizeof svc, "%s", unit->s);

    if      (strcmp(sub, "start")         == 0) {
        snprintf(out->explanation, sizeof out->explanation, "Starts service %s.", svc);
        out->risk = RISK_LOW;
    } else if (strcmp(sub, "stop")        == 0) {
        snprintf(out->explanation, sizeof out->explanation, "Stops service %s.", svc);
        out->risk = RISK_MEDIUM;
    } else if (strcmp(sub, "restart")     == 0) {
        snprintf(out->explanation, sizeof out->explanation, "Restarts service %s.", svc);
        out->risk = RISK_MEDIUM;
    } else if (strcmp(sub, "enable")      == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Enables %s to start automatically at boot.", svc);
        out->risk = RISK_LOW;
    } else if (strcmp(sub, "disable")     == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Prevents %s from starting automatically at boot.", svc);
        out->risk = RISK_LOW;
    } else if (strcmp(sub, "mask")        == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Masks %s - it cannot be started by any means until unmasked.", svc);
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "Masking prevents the service from ever being started, even manually.");
    } else if (strcmp(sub, "daemon-reload") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Reloads systemd manager configuration (picks up unit file changes).");
        out->risk = RISK_LOW;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs systemctl %s on %s.", sub, svc);
        out->risk = RISK_MEDIUM;
    }
}

static void analyze_sudo(const TokList *tl, Analysis *out)
{
    TokList inner = { .n = 0 };
    bool found = false;

    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (!found) {
            if (t->type == TT_FLAG_SHORT || t->type == TT_FLAG_LONG) {
                /* -u/-g eat the next token as their value, skip it */
                if (t->type == TT_FLAG_SHORT &&
                    (t->s[1] == 'u' || t->s[1] == 'g') && t->s[2] == '\0')
                    i++;
                continue;
            }
            found = true;
            inner.t[inner.n]      = *t;
            inner.t[inner.n].type = TT_COMMAND;
            inner.n++;
        } else {
            inner.t[inner.n++] = *t;
            if (inner.n >= TOK_MAX - 1) break;
        }
    }

    if (!found) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Executes a command with elevated root privileges.");
        out->risk = RISK_HIGH;
        out->matched = true;
        return;
    }

    cmd_analyze(&inner, out);
    out->matched = true;

    if (out->risk < RISK_CRITICAL)
        out->risk = (Risk)(out->risk + 1);

    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s", out->explanation);
    snprintf(out->explanation, sizeof out->explanation, "As root: %s", tmp);
}

typedef struct {
    const char *key;
    void (*fn)(const TokList *, Analysis *);
} CmdEntry;

/*
 * bsearch dispatch. O(log n), fast enough for any sane number of commands.
 * table is sorted at runtime on first call - add entries in whatever order
 * you want, the sort handles it. no more "oops wrong alphabetical order" bugs.
 *
 * around 200 entries: think about a hashmap.
 * at 1000+: you definitely should have done it already and this comment haunts you.
 */

/* ---------------------------------------------------------------- network */

static void analyze_ssh(const TokList *tl, Analysis *out)
{
    bool no_host_check = false;
    bool agent_forward = tok_has_short(tl, 'A');
    bool x11_forward   = tok_has_short(tl, 'X') || tok_has_short(tl, 'Y');

    for (int i = 1; i < tl->n - 1; i++) {
        if (strcmp(tl->t[i].s, "-o") == 0 &&
            strstr(tl->t[i+1].s, "StrictHostKeyChecking=no"))
            no_host_check = true;
    }

    const char *host = NULL;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD && tl->t[i].s[0] != '-') {
            host = tl->t[i].s; break;
        }
    }

    char hdesc[128] = "a remote host";
    if (host) snprintf(hdesc, sizeof hdesc, "%s", host);

    snprintf(out->explanation, sizeof out->explanation,
             "Opens an SSH session to %s%s%s.",
             hdesc,
             agent_forward ? " (forwarding your SSH agent)" : "",
             x11_forward   ? " (forwarding X11 display)"   : "");

    out->risk = RISK_SAFE;
    if (agent_forward) {
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "-A forwards your SSH agent - a compromised remote host can use your keys.");
        snprintf(out->safer, sizeof out->safer,
                 "Use -a (lowercase) to explicitly disable agent forwarding.");
    }
    if (no_host_check) {
        out->risk = risk_max(out->risk, RISK_HIGH);
        snprintf(out->warning, sizeof out->warning,
                 "StrictHostKeyChecking=no skips host verification - vulnerable to MITM.");
    }
}

static void analyze_nc(const TokList *tl, Analysis *out)
{
    bool listen  = tok_has_short(tl, 'l') || tok_has_long(tl, "--listen");
    bool exec    = tok_has_short(tl, 'e');  /* -e /bin/sh: shell backdoor */
    bool udp     = tok_has_short(tl, 'u');

    const Tok *port = NULL;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD && tl->t[i].s[0] != '-')
            port = &tl->t[i];
    }

    if (listen && exec) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Opens a %s listener and hands the connection a shell - classic backdoor.",
                 udp ? "UDP" : "TCP");
        out->risk = RISK_CRITICAL;
        snprintf(out->warning, sizeof out->warning,
                 "Anyone who connects gets an interactive shell with your privileges.");
    } else if (listen) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Listens on %s%s for incoming connections.",
                 port ? port->s : "a port",
                 udp ? " (UDP)" : " (TCP)");
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Exposes a port - make sure you know who can reach it.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Connects to %s%s.",
                 port ? port->s : "a host/port",
                 udp ? " over UDP" : " over TCP");
        out->risk = RISK_SAFE;
    }
}

static void analyze_ip(const TokList *tl, Analysis *out)
{
    const char *sub = NULL;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) { sub = tl->t[i].s; break; }
    }

    if (!sub || strcmp(sub, "addr") == 0 || strcmp(sub, "address") == 0 ||
        strcmp(sub, "a")    == 0 ||
        strcmp(sub, "link") == 0 || strcmp(sub, "route") == 0 ||
        strcmp(sub, "r")    == 0 || strcmp(sub, "l") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows network interface and routing information.");
        out->risk = RISK_SAFE;
    } else if (strcmp(sub, "neigh") == 0 || strcmp(sub, "n") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows ARP/neighbour table.");
        out->risk = RISK_SAFE;
    } else {
        /* ip link set, ip addr add/del, ip route add/del - modifying network */
        snprintf(out->explanation, sizeof out->explanation,
                 "Modifies network configuration (%s).", sub);
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Changing network config can drop your connection immediately.");
    }
}

static void analyze_ping(const TokList *tl, Analysis *out)
{
    const Tok *host = tok_first_word(tl, 1);
    char h[128] = "a host";
    if (host) snprintf(h, sizeof h, "%s", host->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Sends ICMP echo packets to %s to check connectivity.", h);
    out->risk = RISK_SAFE;
}

/* ---------------------------------------------------------------- filesystem / system */

static void analyze_mount(const TokList *tl, Analysis *out)
{
    bool bind = tok_has_long(tl, "--bind");
    bool ro   = tok_has_short(tl, 'r') || tok_has_long(tl, "--read-only");

    const Tok *dev = NULL, *mnt = NULL;
    int nw = 0;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type != TT_WORD) continue;
        if (nw == 0) dev = &tl->t[i];
        else         mnt = &tl->t[i];
        nw++;
    }

    if (!dev && !mnt) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists all currently mounted filesystems.");
        out->risk = RISK_SAFE;
        return;
    }

    char src[256] = "(source)", dst[256] = "(mountpoint)";
    if (dev) snprintf(src, sizeof src, "%s", dev->s);
    if (mnt) snprintf(dst, sizeof dst, "%s", mnt->s);

    snprintf(out->explanation, sizeof out->explanation,
             "%s %s at %s%s.",
             bind ? "Bind-mounts" : "Mounts",
             src, dst,
             ro ? " (read-only)" : "");

    out->risk = RISK_MEDIUM;
    if (path_risk(dst) >= RISK_HIGH)
        out->risk = RISK_HIGH;
    if (strstr(src, "/dev/") == src && !ro) {
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "Mounting a block device read-write - existing data on %s may be affected.",
                 src);
    }
}

static void analyze_umount(const TokList *tl, Analysis *out)
{
    const Tok *t = tok_first_word(tl, 1);
    char tgt[256] = "the filesystem";
    if (t) snprintf(tgt, sizeof tgt, "%s", t->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Unmounts %s. Any buffered writes will be flushed first.", tgt);
    out->risk = RISK_LOW;
    snprintf(out->warning, sizeof out->warning,
             "Unmounting a busy filesystem can kill processes using it.");
}

static void analyze_fdisk(const TokList *tl, Analysis *out)
{
    bool list = tok_has_short(tl, 'l') || tok_has_long(tl, "--list");
    const Tok *dev = tok_first_word(tl, 1);
    char d[128] = "a device";
    if (dev) snprintf(d, sizeof d, "%s", dev->s);

    if (list) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists partition tables on all or specified devices.");
        out->risk = RISK_SAFE;
        return;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Opens an interactive partition editor for %s.", d);
    out->risk = RISK_CRITICAL;
    snprintf(out->warning, sizeof out->warning,
             "Writing a new partition table destroys all data on %s.", d);
}

static void analyze_parted(const TokList *tl, Analysis *out)
{
    bool print = false;
    for (int i = 1; i < tl->n; i++)
        if (strcmp(tl->t[i].s, "print") == 0) { print = true; break; }

    const Tok *dev = tok_first_word(tl, 1);
    char d[128] = "a device";
    if (dev) snprintf(d, sizeof d, "%s", dev->s);

    if (print) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Prints the partition table of %s.", d);
        out->risk = RISK_SAFE;
        return;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Modifies partition table of %s.", d);
    out->risk = RISK_CRITICAL;
    snprintf(out->warning, sizeof out->warning,
             "Partition changes on %s are immediate and data loss is likely.", d);
}

static void analyze_chroot(const TokList *tl, Analysis *out)
{
    const Tok *t = tok_first_word(tl, 1);
    char dir[256] = "a directory";
    if (t) snprintf(dir, sizeof dir, "%s", t->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Changes the root filesystem to %s - processes inside see a different /.", dir);
    out->risk = RISK_HIGH;
    snprintf(out->warning, sizeof out->warning,
             "Requires root. If the chroot environment has a shell, it can escape to the real system.");
}

static void analyze_useradd(const TokList *tl, Analysis *out)
{
    bool system  = tok_has_short(tl, 'r') || tok_has_long(tl, "--system");
    bool sudoer  = false;
    for (int i = 1; i < tl->n - 1; i++)
        if ((strcmp(tl->t[i].s, "-G") == 0 || strcmp(tl->t[i].s, "--groups") == 0) &&
            strstr(tl->t[i+1].s, "sudo"))
            sudoer = true;

    const Tok *user = NULL;
    for (int i = tl->n - 1; i >= 1; i--)
        if (tl->t[i].type == TT_WORD) { user = &tl->t[i]; break; }

    char u[128] = "a new user";
    if (user) snprintf(u, sizeof u, "'%s'", user->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Creates %s%s.", u, system ? " (system account, no home dir)" : "");
    out->risk = RISK_MEDIUM;
    if (sudoer) {
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "Adding to the sudo group gives this user full root access.");
    }
}

static void analyze_userdel(const TokList *tl, Analysis *out)
{
    bool remove_home = tok_has_short(tl, 'r') || tok_has_long(tl, "--remove");
    const Tok *user = NULL;
    for (int i = tl->n - 1; i >= 1; i--)
        if (tl->t[i].type == TT_WORD) { user = &tl->t[i]; break; }

    char u[128] = "a user";
    if (user) snprintf(u, sizeof u, "'%s'", user->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Deletes %s%s.",
             u, remove_home ? " and their home directory" : "");
    out->risk = remove_home ? RISK_HIGH : RISK_MEDIUM;
    if (remove_home)
        snprintf(out->warning, sizeof out->warning,
                 "Home directory deletion is permanent.");
}

static void analyze_crontab(const TokList *tl, Analysis *out)
{
    bool edit   = tok_has_short(tl, 'e');
    bool remove = tok_has_short(tl, 'r');
    bool list   = tok_has_short(tl, 'l');

    if (remove) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Removes ALL scheduled cron jobs for this user - no confirmation.");
        out->risk = RISK_HIGH;
        snprintf(out->safer, sizeof out->safer,
                 "crontab -l > crontab.bak first to save a copy.");
    } else if (edit) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Opens the crontab for editing - scheduled commands run as this user.");
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "A malicious crontab entry runs silently on a schedule - common persistence trick.");
    } else if (list) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists all scheduled cron jobs for this user.");
        out->risk = RISK_SAFE;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Manages scheduled cron jobs.");
        out->risk = RISK_LOW;
    }
}

static void analyze_du(const TokList *tl, Analysis *out)
{
    bool human   = tok_has_short(tl, 'h');
    bool summary = tok_has_short(tl, 's') || tok_has_long(tl, "--summarize");
    bool max1    = tok_has_long(tl, "--max-depth");

    const Tok *t = tok_first_word(tl, 1);
    char dir[256] = "the current directory";
    if (t) snprintf(dir, sizeof dir, "%s", t->s);

    snprintf(out->explanation, sizeof out->explanation,
             "%s%s of %s.",
             summary ? "Shows total disk usage" : "Shows disk usage",
             human   ? " in human-readable units" : "",
             dir);

    (void)max1;
    out->risk = RISK_SAFE;
}

static void analyze_lsblk(const TokList *tl, Analysis *out)
{
    (void)tl;
    snprintf(out->explanation, sizeof out->explanation,
             "Lists block devices (disks, partitions, loop devices) and their mount points.");
    out->risk = RISK_SAFE;
}

static void analyze_journalctl(const TokList *tl, Analysis *out)
{
    bool follow  = tok_has_short(tl, 'f') || tok_has_long(tl, "--follow");
    bool unit    = tok_has_short(tl, 'u') || tok_has_long(tl, "--unit");
    bool since   = tok_has_long(tl, "--since");
    bool kernel  = tok_has_short(tl, 'k') || tok_has_long(tl, "--dmesg");

    (void)since; (void)unit;

    if (kernel)
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows kernel log messages (like dmesg, but from the journal).");
    else if (follow)
        snprintf(out->explanation, sizeof out->explanation,
                 "Streams the system journal in real time (like tail -f for systemd logs).");
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Queries the systemd journal log.");
    out->risk = RISK_SAFE;
}

/* ---------------------------------------------------------------- script execution */

static void analyze_bash(const TokList *tl, Analysis *out)
{
    bool inline_cmd = tok_has_short(tl, 'c');
    const Tok *script = tok_first_word(tl, 1);

    if (inline_cmd) {
        /* bash -c "something" */
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs an inline shell command string directly.");
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "-c executes whatever string follows - verify the source before running.");
    } else if (script) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs the shell script '%s'.", script->s);
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Scripts run with your privileges - read it before executing.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Opens an interactive bash shell.");
        out->risk = RISK_SAFE;
    }
}

static void analyze_python(const TokList *tl, Analysis *out)
{
    bool inline_cmd = tok_has_short(tl, 'c');
    const Tok *script = tok_first_word(tl, 1);

    if (inline_cmd) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs an inline Python expression.");
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "-c executes arbitrary Python - make sure you know what it does.");
    } else if (script) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs the Python script '%s'.", script->s);
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Scripts run with your privileges - read it before executing.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Opens an interactive Python interpreter.");
        out->risk = RISK_SAFE;
    }
}

static void analyze_eval(const TokList *tl, Analysis *out)
{
    (void)tl;
    snprintf(out->explanation, sizeof out->explanation,
             "Evaluates and executes its arguments as a shell command.");
    out->risk = RISK_CRITICAL;
    snprintf(out->warning, sizeof out->warning,
             "eval executes whatever string you give it - a common code injection vector. "
             "If the string comes from user input or a network source, this is a serious risk.");
    snprintf(out->safer, sizeof out->safer,
             "If you can avoid eval, do. There's almost always a better way.");
}

static void analyze_base64(const TokList *tl, Analysis *out)
{
    bool decode = tok_has_short(tl, 'd') || tok_has_long(tl, "--decode");

    if (decode) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Decodes base64-encoded input back to its original form.");
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Decoding then piping to bash/sh is a classic obfuscation trick - "
                 "always inspect the decoded content before executing it.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Encodes input as base64. Often used to transfer binary data safely.");
        out->risk = RISK_SAFE;
    }
}

static void analyze_nohup(const TokList *tl, Analysis *out)
{
    const Tok *cmd = tok_first_word(tl, 1);
    char c[128] = "a command";
    if (cmd) snprintf(c, sizeof c, "'%s'", cmd->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Runs %s detached from the terminal - keeps running after you log out, "
             "output goes to nohup.out.", c);
    out->risk = RISK_LOW;
}

/* ---------------------------------------------------------------- package managers */

static void analyze_pip(const TokList *tl, Analysis *out)
{
    const char *sub = NULL;
    for (int i = 1; i < tl->n; i++)
        if (tl->t[i].type == TT_WORD) { sub = tl->t[i].s; break; }

    if (!sub) {
        snprintf(out->explanation, sizeof out->explanation, "Python package manager.");
        out->risk = RISK_SAFE;
        return;
    }

    if (strcmp(sub, "install") == 0) {
        bool user   = tok_has_long(tl, "--user");
        bool upgrade = tok_has_short(tl, 'U') || tok_has_long(tl, "--upgrade");
        snprintf(out->explanation, sizeof out->explanation,
                 "Installs a Python package%s%s.",
                 user    ? " into your user directory (no root needed)" : " system-wide",
                 upgrade ? ", upgrading if already installed" : "");
        out->risk = user ? RISK_LOW : RISK_MEDIUM;
        if (!user)
            snprintf(out->warning, sizeof out->warning,
                     "Installing system-wide overwrites packages used by other tools. "
                     "Prefer --user or a virtual environment.");
    } else if (strcmp(sub, "uninstall") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Removes a Python package.");
        out->risk = RISK_LOW;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs pip %s.", sub);
        out->risk = RISK_SAFE;
    }
}

static void analyze_npm(const TokList *tl, Analysis *out)
{
    const char *sub = NULL;
    for (int i = 1; i < tl->n; i++)
        if (tl->t[i].type == TT_WORD) { sub = tl->t[i].s; break; }

    if (!sub) {
        snprintf(out->explanation, sizeof out->explanation, "Node.js package manager.");
        out->risk = RISK_SAFE;
        return;
    }

    if (strcmp(sub, "install") == 0 || strcmp(sub, "i") == 0) {
        bool global = tok_has_short(tl, 'g') || tok_has_long(tl, "--global");
        snprintf(out->explanation, sizeof out->explanation,
                 "Installs Node.js dependencies from package.json%s.",
                 global ? " globally" : "");
        out->risk = global ? RISK_MEDIUM : RISK_LOW;
        if (global)
            snprintf(out->warning, sizeof out->warning,
                     "Global install affects all Node projects on this machine.");
    } else if (strcmp(sub, "run") == 0 || strcmp(sub, "start") == 0 ||
               strcmp(sub, "test") == 0 || strcmp(sub, "build") == 0) {
        const Tok *script = NULL;
        for (int i = 2; i < tl->n; i++)
            if (tl->t[i].type == TT_WORD) { script = &tl->t[i]; break; }
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs the '%s' script defined in package.json.",
                 script ? script->s : sub);
        out->risk = RISK_LOW;
        snprintf(out->warning, sizeof out->warning,
                 "npm scripts can run arbitrary shell commands - check package.json first.");
    } else if (strcmp(sub, "publish") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Publishes the package to the npm registry. Public by default.");
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "This pushes your code to the public internet unless --access=restricted.");
    } else {
        snprintf(out->explanation, sizeof out->explanation, "Runs npm %s.", sub);
        out->risk = RISK_SAFE;
    }
}

/* ---------------------------------------------------------------- more git subcommands */

static void analyze_git_clone(const TokList *tl, Analysis *out)
{
    bool depth  = tok_has_long(tl, "--depth");
    bool single = tok_has_long(tl, "--single-branch");
    bool bare   = tok_has_long(tl, "--bare");

    const char *url = NULL;
    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (tl->t[i].type == TT_WORD && strcmp(s, "clone") != 0) {
            url = s; break;
        }
    }

    char udesc[256] = "a repository";
    if (url) snprintf(udesc, sizeof udesc, "%s", url);

    snprintf(out->explanation, sizeof out->explanation,
             "Downloads %s%s%s%s.",
             udesc,
             bare   ? " as a bare repository (no working tree)" : "",
             depth  ? " (shallow clone, limited history)" : "",
             single ? " (single branch only)" : "");
    out->risk = RISK_SAFE;
    snprintf(out->warning, sizeof out->warning,
             "The repo may contain scripts or Makefiles that run code - inspect before building.");
}

static void analyze_git_pull(const TokList *tl, Analysis *out)
{
    bool rebase = tok_has_long(tl, "--rebase");
    bool ff     = tok_has_long(tl, "--ff-only");

    snprintf(out->explanation, sizeof out->explanation,
             "Fetches and %s remote changes into the current branch.",
             rebase ? "rebases" : "merges");
    out->risk = RISK_LOW;
    if (rebase)
        snprintf(out->warning, sizeof out->warning,
                 "--rebase rewrites local commits - don't do this on shared branches.");
    if (!rebase && !ff)
        snprintf(out->safer, sizeof out->safer,
                 "git pull --ff-only fails instead of creating a merge commit, keeping history clean.");
}

static void analyze_git_commit(const TokList *tl, Analysis *out)
{
    bool amend   = tok_has_long(tl, "--amend");
    bool all     = tok_has_short(tl, 'a') || tok_has_long(tl, "--all");
    bool no_edit = tok_has_long(tl, "--no-edit");

    if (amend) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Modifies the last commit (message%s).",
                 no_edit ? ", keeping the existing message" : " and/or staged changes");
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "--amend rewrites history. If you've already pushed, you'll need --force.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Records staged changes as a new commit%s.",
                 all ? " (including all modified tracked files)" : "");
        out->risk = RISK_SAFE;
    }
}

static void analyze_git_merge(const TokList *tl, Analysis *out)
{
    bool no_ff    = tok_has_long(tl, "--no-ff");
    bool squash   = tok_has_long(tl, "--squash");
    bool abort    = tok_has_long(tl, "--abort");

    if (abort) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Aborts an in-progress merge and restores the pre-merge state.");
        out->risk = RISK_LOW;
        return;
    }

    const Tok *branch = NULL;
    for (int i = 1; i < tl->n; i++)
        if (tl->t[i].type == TT_WORD && strcmp(tl->t[i].s, "merge") != 0)
        { branch = &tl->t[i]; break; }

    char b[128] = "another branch";
    if (branch) snprintf(b, sizeof b, "'%s'", branch->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Merges %s into the current branch%s.",
             b,
             squash ? " (squashing all commits into one)" :
             no_ff  ? " (always creates a merge commit)" : "");
    out->risk = RISK_LOW;
}

static void analyze_git_rebase(const TokList *tl, Analysis *out)
{
    bool interactive = tok_has_short(tl, 'i') || tok_has_long(tl, "--interactive");
    bool abort       = tok_has_long(tl, "--abort");
    bool cont        = tok_has_long(tl, "--continue");
    bool onto        = tok_has_long(tl, "--onto");

    if (abort) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Aborts an in-progress rebase and returns to the original branch state.");
        out->risk = RISK_LOW;
        return;
    }
    if (cont) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Continues a paused rebase after resolving conflicts.");
        out->risk = RISK_LOW;
        return;
    }

    const Tok *base = NULL;
    for (int i = 1; i < tl->n; i++)
        if (tl->t[i].type == TT_WORD && strcmp(tl->t[i].s, "rebase") != 0)
        { base = &tl->t[i]; break; }

    char b[128] = "another branch";
    if (base) snprintf(b, sizeof b, "'%s'", base->s);

    snprintf(out->explanation, sizeof out->explanation,
             "%srebases current branch onto %s%s - rewrites commit history.",
             interactive ? "Interactively " : "",
             b,
             onto ? " (with explicit base via --onto)" : "");
    out->risk = RISK_HIGH;
    snprintf(out->warning, sizeof out->warning,
             "Rebase rewrites commits. Force-push will be required if already pushed.");
    snprintf(out->safer, sizeof out->safer,
             "Only rebase branches that haven't been pushed, or use git merge instead.");
}

static void analyze_git_stash(const TokList *tl, Analysis *out)
{
    const char *sub = NULL;
    for (int i = 1; i < tl->n; i++)
        if (tl->t[i].type == TT_WORD && strcmp(tl->t[i].s, "stash") != 0)
        { sub = tl->t[i].s; break; }

    if (!sub || strcmp(sub, "push") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Saves uncommitted changes to a temporary stack and restores a clean working tree.");
        out->risk = RISK_SAFE;
    } else if (strcmp(sub, "pop") == 0 || strcmp(sub, "apply") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Restores the most recent stashed changes back to the working tree.");
        out->risk = RISK_SAFE;
    } else if (strcmp(sub, "drop") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Permanently deletes a stash entry.");
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "Dropped stashes are gone - there's no recovery.");
    } else if (strcmp(sub, "clear") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Deletes ALL stash entries permanently.");
        out->risk = RISK_HIGH;
        snprintf(out->warning, sizeof out->warning,
                 "This removes every stash you have - unrecoverable.");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs git stash %s.", sub);
        out->risk = RISK_SAFE;
    }
}

static void analyze_git_diff(const TokList *tl, Analysis *out)
{
    bool cached  = tok_has_long(tl, "--cached") || tok_has_long(tl, "--staged");
    bool stat    = tok_has_long(tl, "--stat");
    bool check   = tok_has_long(tl, "--check");

    snprintf(out->explanation, sizeof out->explanation,
             "Shows %s%s.",
             cached ? "staged (not yet committed) " : "",
             stat   ? "a summary of changed files" :
             check  ? "whitespace issues in the diff" :
                      "a line-by-line diff of changes");
    out->risk = RISK_SAFE;
    (void)check;
}

/* ---------------------------------------------------------------- more docker */

static void analyze_docker_build(const TokList *tl, Analysis *out)
{
    bool no_cache = tok_has_long(tl, "--no-cache");
    const char *tag = tok_long_val(tl, "-t");
    char t[128] = "(untagged)";
    if (tag) snprintf(t, sizeof t, "'%s'", tag);

    snprintf(out->explanation, sizeof out->explanation,
             "Builds a Docker image %s from a Dockerfile%s.",
             t, no_cache ? " (ignoring cache)" : "");
    out->risk = RISK_LOW;
    snprintf(out->warning, sizeof out->warning,
             "The Dockerfile may run arbitrary commands during build - inspect it first.");
}

static void analyze_docker_ps(const TokList *tl, Analysis *out)
{
    bool all = tok_has_short(tl, 'a') || tok_has_long(tl, "--all");
    snprintf(out->explanation, sizeof out->explanation,
             "Lists %s Docker containers.",
             all ? "all (including stopped)" : "running");
    out->risk = RISK_SAFE;
}

static void analyze_docker_stop(const TokList *tl, Analysis *out)
{
    bool all_flag = false;
    for (int i = 1; i < tl->n; i++)
        if (strcmp(tl->t[i].s, "$(docker ps -q)") == 0) all_flag = true;

    const Tok *ct = NULL;
    for (int i = 1; i < tl->n; i++)
        if (tl->t[i].type == TT_WORD && strcmp(tl->t[i].s, "stop") != 0)
        { ct = &tl->t[i]; break; }

    char c[128] = "a container";
    if (ct) snprintf(c, sizeof c, "container '%s'", ct->s);

    snprintf(out->explanation, sizeof out->explanation,
             "Gracefully stops %s%s (sends SIGTERM, waits, then SIGKILL).",
             all_flag ? "ALL running containers" : c,
             all_flag ? "" : "");
    out->risk = all_flag ? RISK_HIGH : RISK_LOW;
}

/* sheer knows itself. obviously. */
static void analyze_sheer(const TokList *tl, Analysis *out)
{
    /* find the subcommand if any */
    const char *sub = tl->n > 1 ? tl->t[1].s : NULL;

    if (!sub) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs sheer with no arguments - shows usage.");
    } else if (strcmp(sub, "run") == 0) {
        const char *cmd = tl->n > 2 ? tl->t[2].s : NULL;
        if (cmd)
            snprintf(out->explanation, sizeof out->explanation,
                     "Explains '%s', shows its risk level, then asks before running it.", cmd);
        else
            snprintf(out->explanation, sizeof out->explanation,
                     "Explains a command, shows its risk level, then asks before running it.");
    } else if (strcmp(sub, "gen") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Generates a shell command from a plain-English description using an LLM.");
    } else if (strcmp(sub, "config") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows or edits sheer's config (~/.config/sheer/config).");
    } else {
        /* treat the rest as a command being explained */
        snprintf(out->explanation, sizeof out->explanation,
                 "Explains '%s' - shows what it does and how risky it is.", sub);
    }
    out->risk = RISK_SAFE;
}

static void analyze_shrun(const TokList *tl, Analysis *out)
{
    const char *cmd = tl->n > 1 ? tl->t[1].s : NULL;
    if (cmd)
        snprintf(out->explanation, sizeof out->explanation,
                 "Shell wrapper: explains '%s', shows risk, prompts y/N before running it. "
                 "Defined by sheer's install - it's `eval \"$(sheer run ...)\"` under the hood.",
                 cmd);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Shell wrapper around `sheer run`: explains the command, shows risk, "
                 "prompts y/N before running. Defined by sheer's install.");
    out->risk = RISK_SAFE;
}

/* ---------------------------------------------------------------- misc utilities */

static void analyze_unzip(const TokList *tl, Analysis *out)
{
    bool overwrite = tok_has_short(tl, 'o');
    bool list      = tok_has_short(tl, 'l');
    const Tok *t   = tok_first_word(tl, 1);
    char f[256] = "an archive";
    if (t) snprintf(f, sizeof f, "'%s'", t->s);

    if (list) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists the contents of %s without extracting.", f);
        out->risk = RISK_SAFE;
        return;
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Extracts %s%s.",
             f, overwrite ? " (overwrites existing files without prompting)" : "");
    out->risk = overwrite ? RISK_MEDIUM : RISK_SAFE;
    if (overwrite)
        snprintf(out->safer, sizeof out->safer,
                 "Drop -o to be prompted before overwriting existing files.");
}

static void analyze_env(const TokList *tl, Analysis *out)
{
    bool clear = tok_has_short(tl, 'i') || tok_has_long(tl, "--ignore-environment");

    if (tl->n == 1) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Prints all current environment variables.");
    } else if (clear) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs a command in a clean environment (no inherited variables).");
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs a command with specific environment variables set.");
    }
    out->risk = RISK_SAFE;
}

static void analyze_which(const TokList *tl, Analysis *out)
{
    const Tok *t = tok_first_word(tl, 1);
    char c[128] = "a command";
    if (t) snprintf(c, sizeof c, "'%s'", t->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Finds the full path of %s in your PATH.", c);
    out->risk = RISK_SAFE;
}

/* ---------------------------------------------------------------- builtins
 * cd, echo, ls... the stuff everyone uses every second.
 * embarrassing that these weren't here from the start, but here we are.
 * ----------------------------------------------------------------- */

static void analyze_cd(const TokList *tl, Analysis *out)
{
    const Tok *dest = tok_first_word(tl, 1);
    char dir[256] = "the home directory";
    Risk r = RISK_SAFE;
    if (dest) {
        snprintf(dir, sizeof dir, "%s", dest->s);
        /* cd / or cd /root is worth flagging */
        r = path_risk(dest->s) >= RISK_HIGH ? RISK_LOW : RISK_SAFE;
    }
    snprintf(out->explanation, sizeof out->explanation,
             "Changes the current directory to %s.", dir);
    out->risk = r;
}

static void analyze_echo(const TokList *tl, Analysis *out)
{
    bool no_newline = tok_has_short(tl, 'n');
    bool interpret  = tok_has_short(tl, 'e');

    /* grab whatever comes after the flags as the message */
    char msg[256] = "";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(msg, sizeof msg, " '%s'", tl->t[i].s);
            break;
        }
    }

    snprintf(out->explanation, sizeof out->explanation,
             "Prints%s to stdout%s.",
             msg,
             no_newline ? " (no trailing newline)" :
             interpret  ? " (interpreting escape sequences)" : "");
    out->risk = RISK_SAFE;
}

static void analyze_ls(const TokList *tl, Analysis *out)
{
    bool all     = tok_has_short(tl, 'a') || tok_has_short(tl, 'A');
    bool human   = tok_has_short(tl, 'h');
    bool long_f  = tok_has_short(tl, 'l');
    bool recurse = tok_has_short(tl, 'R');

    const Tok *target = tok_first_word(tl, 1);
    char dir[256] = "the current directory";
    if (target) snprintf(dir, sizeof dir, "%s", target->s);

    char detail[64] = "";
    if (long_f && human) snprintf(detail, sizeof detail, " (long format, human sizes)");
    else if (long_f)     snprintf(detail, sizeof detail, " (long format)");

    snprintf(out->explanation, sizeof out->explanation,
             "Lists %s%s%s%s.",
             all ? "all files (including hidden) in " : "files in ",
             dir, detail,
             recurse ? " recursively" : "");
    out->risk = RISK_SAFE;
}

static void analyze_mkdir(const TokList *tl, Analysis *out)
{
    bool parents = tok_has_short(tl, 'p') || tok_has_long(tl, "--parents");
    const Tok *t = tok_first_word(tl, 1);
    char dir[256] = "a directory";
    Risk r = RISK_SAFE;
    if (t) {
        snprintf(dir, sizeof dir, "%s", t->s);
        r = path_risk(t->s) >= RISK_HIGH ? RISK_LOW : RISK_SAFE;
    }
    snprintf(out->explanation, sizeof out->explanation,
             "Creates directory %s%s.",
             dir, parents ? " (and any missing parent directories)" : "");
    out->risk = r;
}

static void analyze_touch(const TokList *tl, Analysis *out)
{
    const Tok *t = tok_first_word(tl, 1);
    char file[256] = "a file";
    if (t) snprintf(file, sizeof file, "%s", t->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Creates %s if it doesn't exist, or updates its timestamp.", file);
    out->risk = RISK_SAFE;
}

static void analyze_export(const TokList *tl, Analysis *out)
{
    const Tok *t = tok_first_word(tl, 1);
    char var[128] = "a variable";
    if (t) snprintf(var, sizeof var, "%s", t->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Sets environment variable %s for this shell and any child processes.", var);
    out->risk = RISK_SAFE;
}

static void analyze_source(const TokList *tl, Analysis *out)
{
    const Tok *t = tok_first_word(tl, 1);
    char file[256] = "a script";
    if (t) snprintf(file, sizeof file, "%s", t->s);
    snprintf(out->explanation, sizeof out->explanation,
             "Runs %s in the current shell - any variables or functions it defines stick around.",
             file);
    out->risk = RISK_LOW;
    snprintf(out->warning, sizeof out->warning,
             "The script runs with your privileges and can modify your environment.");
}

static void analyze_printf(const TokList *tl, Analysis *out)
{
    (void)tl;
    snprintf(out->explanation, sizeof out->explanation,
             "Prints formatted output to stdout (like C's printf).");
    out->risk = RISK_SAFE;
}

/* --------------------------------------------------------------- pipe utils
 * grep, awk, sed, xargs, ps... mostly harmless.
 * xargs is the sneaky one - it multiplies whatever dangerous thing you pipe in.
 * ----------------------------------------------------------------- */

static void analyze_apt(const TokList *tl, Analysis *out)
{
    const char *sub = NULL;
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) { sub = tl->t[i].s; break; }
    }

    if (!sub) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Debian/Ubuntu package manager.");
        out->risk = RISK_SAFE;
        return;
    }

    if (strcmp(sub, "install") == 0 || strcmp(sub, "add") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Installs one or more packages from the repository.");
        out->risk = RISK_LOW;
    } else if (strcmp(sub, "remove") == 0 || strcmp(sub, "purge") == 0) {
        bool purge = strcmp(sub, "purge") == 0;
        snprintf(out->explanation, sizeof out->explanation,
                 "%s a package%s.",
                 purge ? "Removes" : "Uninstalls",
                 purge ? " and all its config files" : "");
        out->risk = RISK_LOW;
        if (purge)
            snprintf(out->safer, sizeof out->safer,
                     "Use 'apt remove' to keep config files (easier to restore).");
    } else if (strcmp(sub, "autoremove") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Removes packages that were installed as dependencies and are no longer needed.");
        out->risk = RISK_LOW;
    } else if (strcmp(sub, "upgrade") == 0 || strcmp(sub, "full-upgrade") == 0 ||
               strcmp(sub, "dist-upgrade") == 0) {
        bool dist = strcmp(sub, "full-upgrade") == 0 || strcmp(sub, "dist-upgrade") == 0;
        snprintf(out->explanation, sizeof out->explanation,
                 "Upgrades all installed packages%s.",
                 dist ? " (may remove conflicting packages)" : "");
        out->risk = dist ? RISK_MEDIUM : RISK_LOW;
        if (dist)
            snprintf(out->warning, sizeof out->warning,
                     "dist-upgrade/full-upgrade can remove packages to resolve conflicts.");
    } else if (strcmp(sub, "update") == 0) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Refreshes the list of available packages. Doesn't install anything.");
        out->risk = RISK_SAFE;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Runs apt %s.", sub);
        out->risk = RISK_SAFE;
    }
}

static void analyze_chattr(const TokList *tl, Analysis *out)
{
    bool immutable = false;
    bool append    = false;
    bool removing  = false; /* chattr -i removes, chattr +i adds */

    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (s[0] == '+' || s[0] == '-' || s[0] == '=') {
            if (s[0] == '-') removing = true;
            if (strchr(s, 'i')) immutable = true;
            if (strchr(s, 'a')) append    = true;
        }
    }

    /* skip the attribute spec (+i, -a, =i...) to get the actual path */
    const Tok *target = NULL;
    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (tl->t[i].type == TT_WORD &&
            s[0] != '+' && s[0] != '-' && s[0] != '=')
        { target = &tl->t[i]; break; }
    }
    char tgt[256] = "the file";
    if (target) snprintf(tgt, sizeof tgt, "%s", target->s);

    if (immutable && !removing) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Sets the immutable flag on %s - even root can't modify or delete it.", tgt);
        out->risk = RISK_MEDIUM;
        snprintf(out->warning, sizeof out->warning,
                 "An immutable file can't be changed until you run chattr -i.");
    } else if (immutable && removing) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Removes the immutable flag from %s, making it writable again.", tgt);
        out->risk = RISK_LOW;
    } else if (append) {
        snprintf(out->explanation, sizeof out->explanation,
                 "Sets append-only mode on %s - data can be added but not removed.", tgt);
        out->risk = RISK_LOW;
    } else {
        snprintf(out->explanation, sizeof out->explanation,
                 "Changes extended filesystem attributes on %s.", tgt);
        out->risk = RISK_LOW;
    }
}

static void analyze_df(const TokList *tl, Analysis *out)
{
    bool human  = tok_has_short(tl, 'h') || tok_has_long(tl, "--human-readable");
    bool inodes = tok_has_short(tl, 'i') || tok_has_long(tl, "--inodes");

    if (inodes)
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows inode usage for all mounted filesystems.");
    else if (human)
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows disk space usage in human-readable units (KB/MB/GB).");
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Shows disk space usage for all mounted filesystems (in 1K blocks).");

    out->risk = RISK_SAFE;
}

static void analyze_awk(const TokList *tl, Analysis *out)
{
    const char *sep = tok_long_val(tl, "-F");

    char prog[64] = "";
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type != TT_WORD || t->s[0] == '-') continue;
        if (i > 1 && strcmp(tl->t[i-1].s, "-F") == 0) continue; /* -F value, skip */
        snprintf(prog, sizeof prog, " '%s'", t->s);
        break;
    }

    if (sep)
        snprintf(out->explanation, sizeof out->explanation,
                 "Processes text line by line (field separator '%s')%s.",
                 sep, prog);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Processes text line by line%s.", prog);

    out->risk = RISK_SAFE;
}

static void analyze_cat(const TokList *tl, Analysis *out)
{
    char target[256] = "stdin";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(target, sizeof target, "%s", tl->t[i].s);
            break;
        }
    }
    snprintf(out->explanation, sizeof out->explanation,
             "Concatenates and prints %s to stdout.", target);
    out->risk = RISK_SAFE;
}

static void analyze_cut(const TokList *tl, Analysis *out)
{
    const char *delim = tok_long_val(tl, "-d");
    bool fields = tok_has_short(tl, 'f');
    bool bytes  = tok_has_short(tl, 'b');

    if (bytes)
        snprintf(out->explanation, sizeof out->explanation,
                 "Extracts a byte range from each line.");
    else if (fields && delim)
        snprintf(out->explanation, sizeof out->explanation,
                 "Splits lines on '%s' and extracts the selected fields.", delim);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Extracts a column or byte range from each input line.");

    out->risk = RISK_SAFE;
}

static void analyze_grep(const TokList *tl, Analysis *out)
{
    bool recursive = tok_has_short(tl, 'r') || tok_has_short(tl, 'R');
    bool invert    = tok_has_short(tl, 'v');
    bool fixed     = tok_has_short(tl, 'F');
    bool extended  = tok_has_short(tl, 'E') || tok_has_long(tl, "--extended-regexp");

    char pattern[128] = "";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(pattern, sizeof pattern, " for '%s'", tl->t[i].s);
            break;
        }
    }

    const char *engine = fixed ? "fixed string" : extended ? "regex (ERE)" : "regex";
    snprintf(out->explanation, sizeof out->explanation,
             "Searches%s using %s%s%s.",
             pattern, engine,
             recursive ? " recursively" : "",
             invert    ? ", printing non-matching lines" : "");

    out->risk = RISK_SAFE;
}

static void analyze_head(const TokList *tl, Analysis *out)
{
    const char *nstr = tok_long_val(tl, "-n");
    char n[32] = "10";
    if (nstr) snprintf(n, sizeof n, "%s", nstr);

    snprintf(out->explanation, sizeof out->explanation,
             "Prints the first %s lines of input.", n);
    out->risk = RISK_SAFE;
}

static void analyze_ps(const TokList *tl, Analysis *out)
{
    /* ps aux: BSD-style flags come without a leading dash, so tok_has_short
     * won't find them. check for the literal token "aux" or "ax" too. */
    bool bsd_aux = false;
    for (int i = 1; i < tl->n; i++) {
        const char *s = tl->t[i].s;
        if (strcmp(s, "aux") == 0 || strcmp(s, "ax") == 0 ||
            strcmp(s, "axu") == 0 || strcmp(s, "axuf") == 0)
            bsd_aux = true;
    }
    bool aux  = bsd_aux ||
                (tok_has_short(tl, 'a') &&
                 tok_has_short(tl, 'u') &&
                 tok_has_short(tl, 'x'));
    bool ef   = tok_has_short(tl, 'e') && tok_has_short(tl, 'f');

    if (aux || ef)
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists all running processes with CPU, memory, and command details.");
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Lists running processes for the current terminal.");

    out->risk = RISK_SAFE;
}

static void analyze_sed(const TokList *tl, Analysis *out)
{
    bool inplace = tok_has_short(tl, 'i') || tok_has_long(tl, "--in-place");

    char expr[128] = "";
    for (int i = 1; i < tl->n; i++) {
        const Tok *t = &tl->t[i];
        if (t->type == TT_WORD && t->s[0] != '-') {
            snprintf(expr, sizeof expr, " expression '%s'", t->s);
            break;
        }
    }

    if (inplace)
        snprintf(out->explanation, sizeof out->explanation,
                 "Applies a stream transformation%s directly to the file(s) in-place.",
                 expr);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Applies a stream transformation%s and writes to stdout.", expr);

    out->risk = inplace ? RISK_MEDIUM : RISK_SAFE;
    if (inplace)
        snprintf(out->safer, sizeof out->safer,
                 "Drop -i to preview changes first, then add it once sure.");
}

static void analyze_sort(const TokList *tl, Analysis *out)
{
    bool unique  = tok_has_short(tl, 'u');
    bool reverse = tok_has_short(tl, 'r');
    bool numeric = tok_has_short(tl, 'n');

    char details[128] = "";
    int  dc = 0;
    if (numeric) { snprintf(details + dc, sizeof details - (size_t)dc, "numerically"); dc = (int)strlen(details); }
    if (reverse) { snprintf(details + dc, sizeof details - (size_t)dc, "%sin reverse",  dc ? ", " : ""); dc = (int)strlen(details); }
    if (unique)  { snprintf(details + dc, sizeof details - (size_t)dc, "%s(dedup)",     dc ? " " : ""); }

    if (details[0])
        snprintf(out->explanation, sizeof out->explanation,
                 "Sorts lines %s.", details);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Sorts lines alphabetically.");

    out->risk = RISK_SAFE;
}

static void analyze_tail(const TokList *tl, Analysis *out)
{
    const char *nstr = tok_long_val(tl, "-n");
    bool follow = tok_has_short(tl, 'f') || tok_has_long(tl, "--follow");
    char n[32] = "10";
    if (nstr) snprintf(n, sizeof n, "%s", nstr);

    if (follow)
        snprintf(out->explanation, sizeof out->explanation,
                 "Streams the last %s lines of a file and keeps watching for new output.",
                 n);
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Prints the last %s lines of input.", n);

    out->risk = RISK_SAFE;
}

static void analyze_tee(const TokList *tl, Analysis *out)
{
    bool append = tok_has_short(tl, 'a');
    char file[256] = "(file)";
    for (int i = 1; i < tl->n; i++) {
        if (tl->t[i].type == TT_WORD) {
            snprintf(file, sizeof file, "%s", tl->t[i].s);
            break;
        }
    }
    snprintf(out->explanation, sizeof out->explanation,
             "Writes stdin to both stdout and %s%s (useful for logging mid-pipeline).",
             file, append ? " (appending)" : "");
    out->risk = RISK_SAFE;
}

static void analyze_uniq(const TokList *tl, Analysis *out)
{
    bool dup    = tok_has_short(tl, 'd');
    bool unique = tok_has_short(tl, 'u');
    bool count  = tok_has_short(tl, 'c');

    if (dup)
        snprintf(out->explanation, sizeof out->explanation,
                 "Prints only duplicate adjacent lines.");
    else if (unique)
        snprintf(out->explanation, sizeof out->explanation,
                 "Prints only unique (non-repeated) adjacent lines.");
    else if (count)
        snprintf(out->explanation, sizeof out->explanation,
                 "Collapses duplicate adjacent lines and prefixes each with its count.");
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Removes consecutive duplicate lines from input.");

    out->risk = RISK_SAFE;
}

static void analyze_wc(const TokList *tl, Analysis *out)
{
    bool lines = tok_has_short(tl, 'l');
    bool words = tok_has_short(tl, 'w');
    bool bytes = tok_has_short(tl, 'c');

    if (lines && !words && !bytes)
        snprintf(out->explanation, sizeof out->explanation, "Counts lines.");
    else if (words && !lines && !bytes)
        snprintf(out->explanation, sizeof out->explanation, "Counts words.");
    else if (bytes && !lines && !words)
        snprintf(out->explanation, sizeof out->explanation, "Counts bytes.");
    else
        snprintf(out->explanation, sizeof out->explanation,
                 "Counts lines, words, and bytes in input.");

    out->risk = RISK_SAFE;
}

static void analyze_xargs(const TokList *tl, Analysis *out)
{
    /* find the command xargs will run - first WORD that isn't a flag or a flag value
     * known flags with values: -I, -n, -P, -L, -s, -d (we skip the following token)
     */
    static const char *const valued[] = { "-I", "-n", "-P", "-L", "-s", "-d", NULL };
    int skip_next = 0;
    const char *subcmd = "a command";
    for (int i = 1; i < tl->n; i++) {
        if (skip_next) { skip_next = 0; continue; }
        const Tok *t = &tl->t[i];
        if (t->type != TT_WORD) continue;
        if (t->s[0] == '-') {
            for (int j = 0; valued[j]; j++)
                if (strcmp(t->s, valued[j]) == 0) { skip_next = 1; break; }
            continue;
        }
        subcmd = t->s;
        break;
    }

    bool null_sep = tok_has_short(tl, '0') || tok_has_long(tl, "--null");

    /* risk follows the sub-command: rm/kill/etc are dangerous */
    Risk sub_risk = RISK_SAFE;
    if (strcmp(subcmd, "rm")    == 0 || strcmp(subcmd, "shred") == 0)  sub_risk = RISK_HIGH;
    if (strcmp(subcmd, "kill")  == 0 || strcmp(subcmd, "killall") == 0) sub_risk = RISK_HIGH;
    if (strcmp(subcmd, "chmod") == 0 || strcmp(subcmd, "chown") == 0)   sub_risk = RISK_MEDIUM;
    if (strcmp(subcmd, "sudo")  == 0)                                   sub_risk = RISK_HIGH;

    snprintf(out->explanation, sizeof out->explanation,
             "Runs %s once per input item%s.",
             subcmd,
             null_sep ? " (NUL-delimited, safe for filenames with spaces)" : "");

    out->risk = sub_risk;
    if (sub_risk >= RISK_HIGH)
        snprintf(out->warning, sizeof out->warning,
                 "xargs amplifies the effect of '%s' - one line per run.", subcmd);
    if (sub_risk >= RISK_HIGH)
        snprintf(out->safer, sizeof out->safer,
                 "Try: xargs echo %s first to preview what would be passed.", subcmd);
}

static CmdEntry cmd_table[] = {

    /* shell builtins & everyday utils */
    { "cat",            analyze_cat           },
    { "cd",             analyze_cd            },
    { "echo",           analyze_echo          },
    { "env",            analyze_env           },
    { "export",         analyze_export        },
    { "ls",             analyze_ls            },
    { "mkdir",          analyze_mkdir         },
    { "nohup",          analyze_nohup         },
    { "printf",         analyze_printf        },
    { "source",         analyze_source        },
    { "touch",          analyze_touch         },
    { "which",          analyze_which         },

    /* file operations */
    { "chattr",         analyze_chattr        },
    { "chmod",          analyze_chmod         },
    { "chown",          analyze_chown         },
    { "cp",             analyze_cp            },
    { "dd",             analyze_dd            },
    { "find",           analyze_find          },
    { "ln",             analyze_ln            },
    { "mv",             analyze_mv            },
    { "rm",             analyze_rm            },
    { "rsync",          analyze_rsync         },
    { "tar",            analyze_tar           },
    { "unzip",          analyze_unzip         },

    /* text processing (pipeline staples) */
    { "awk",            analyze_awk           },
    { "cut",            analyze_cut           },
    { "grep",           analyze_grep          },
    { "head",           analyze_head          },
    { "sed",            analyze_sed           },
    { "sort",           analyze_sort          },
    { "tail",           analyze_tail          },
    { "tee",            analyze_tee           },
    { "uniq",           analyze_uniq          },
    { "wc",             analyze_wc            },
    { "xargs",          analyze_xargs         },

    /* system info / monitoring */
    { "df",             analyze_df            },
    { "du",             analyze_du            },
    { "journalctl",     analyze_journalctl    },
    { "lsblk",          analyze_lsblk         },
    { "ps",             analyze_ps            },

    /* process management */
    { "kill",           analyze_kill          },
    { "killall",        analyze_killall       },
    { "pkill",          analyze_pkill         },

    /* network */
    { "curl",           analyze_curl          },
    { "ip",             analyze_ip            },
    { "nc",             analyze_nc            },
    { "netcat",         analyze_nc            },
    { "ping",           analyze_ping          },
    { "scp",            analyze_scp           },
    { "ssh",            analyze_ssh           },
    { "wget",           analyze_wget          },

    /* filesystem / disk management */
    { "chroot",         analyze_chroot        },
    { "fdisk",          analyze_fdisk         },
    { "mkfs",           analyze_mkfs          },
    { "mount",          analyze_mount         },
    { "parted",         analyze_parted        },
    { "umount",         analyze_umount        },

    /* system administration */
    { "adduser",        analyze_useradd       },
    { "chroot",         analyze_chroot        },  /* duplicate intentional - alias */
    { "crontab",        analyze_crontab       },
    { "iptables",       analyze_iptables      },
    { "sudo",           analyze_sudo          },
    { "systemctl",      analyze_systemctl     },
    { "useradd",        analyze_useradd       },
    { "userdel",        analyze_userdel       },

    /* script / code execution - the scary ones */
    { "base64",         analyze_base64        },
    { "bash",           analyze_bash          },
    { "eval",           analyze_eval          },
    { "python",         analyze_python        },
    { "python3",        analyze_python        },
    { "sh",             analyze_bash          },

    /* package managers */
    { "apt",            analyze_apt           },
    { "apt-get",        analyze_apt           },
    { "npm",            analyze_npm           },
    { "pip",            analyze_pip           },
    { "pip3",           analyze_pip           },

    /* git */
    { "git checkout",   analyze_git_checkout  },
    { "git clean",      analyze_git_clean     },
    { "git clone",      analyze_git_clone     },
    { "git commit",     analyze_git_commit    },
    { "git diff",       analyze_git_diff      },
    { "git merge",      analyze_git_merge     },
    { "git pull",       analyze_git_pull      },
    { "git push",       analyze_git_push      },
    { "git rebase",     analyze_git_rebase    },
    { "git reset",      analyze_git_reset     },
    { "git stash",      analyze_git_stash     },

    /* sheer itself - why not */
    { "sheer",          analyze_sheer         },
    { "shrun",          analyze_shrun         },

    /* docker */
    { "docker build",   analyze_docker_build  },
    { "docker exec",    analyze_docker_exec   },
    { "docker ps",      analyze_docker_ps     },
    { "docker rm",      analyze_docker_rm     },
    { "docker run",     analyze_docker_run    },
    { "docker stop",    analyze_docker_stop   },
};

#define TABLE_LEN ((int)(sizeof cmd_table / sizeof cmd_table[0]))

/* bsearch: key is a plain string, entry is CmdEntry */
static int entry_cmp(const void *key, const void *entry)
{
    return strcmp((const char *)key, ((const CmdEntry *)entry)->key);
}

/* qsort: both sides are CmdEntry */
static int entry_cmp_sort(const void *a, const void *b)
{
    return strcmp(((const CmdEntry *)a)->key, ((const CmdEntry *)b)->key);
}

static void ensure_table_sorted(void)
{
    static bool done = false;
    if (done) return;
    qsort(cmd_table, (size_t)TABLE_LEN, sizeof cmd_table[0], entry_cmp_sort);
    done = true;
}

static bool is_compound_prefix(const char *name)
{
    static const char *const prefixes[] = {
        "docker", "git", "kubectl", "npm", "pip",
    };
    for (size_t i = 0; i < sizeof prefixes / sizeof prefixes[0]; i++)
        if (strcmp(name, prefixes[i]) == 0) return true;
    return false;
}

void cmd_analyze(const TokList *tl, Analysis *out)
{
    ensure_table_sorted();
    memset(out, 0, sizeof *out);

    if (tl->n == 0) return;

    const char *raw   = tl->t[0].s;
    const char *slash = strrchr(raw, '/');
    const char *cmd   = slash ? slash + 1 : raw; /* strip path prefix */

    if (strncmp(cmd, "mkfs", 4) == 0) {
        analyze_mkfs(tl, out);
        out->matched = true;
        snprintf(out->source, sizeof out->source, "local rules");
        return;
    }

    /* ip6tables: same semantics as iptables */
    if (strcmp(cmd, "ip6tables") == 0) {
        analyze_iptables(tl, out);
        out->matched = true;
        snprintf(out->source, sizeof out->source, "local rules");
        return;
    }

    char key[128];

    if (is_compound_prefix(cmd)) {
        const char *sub = NULL;
        /* skip flags between cmd and subcommand, e.g. git -C /path reset */
        for (int i = 1; i < tl->n; i++) {
            if (tl->t[i].type == TT_WORD) { sub = tl->t[i].s; break; }
        }
        if (sub) {
            snprintf(key, sizeof key, "%s %s", cmd, sub);
            const CmdEntry *e = bsearch(key, cmd_table,
                                        (size_t)TABLE_LEN, sizeof cmd_table[0],
                                        entry_cmp);
            if (e) {
                e->fn(tl, out);
                out->matched = true;
                snprintf(out->source, sizeof out->source, "local rules");
                return;
            }
        }
    }

    snprintf(key, sizeof key, "%s", cmd);
    const CmdEntry *e = bsearch(key, cmd_table,
                                (size_t)TABLE_LEN, sizeof cmd_table[0],
                                entry_cmp);
    if (e) {
        e->fn(tl, out);
        out->matched = true;
        snprintf(out->source, sizeof out->source, "local rules");
    }
}
