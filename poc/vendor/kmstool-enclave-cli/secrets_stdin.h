/*
 * ROT-8 — read the secret-bearing arguments from stdin instead of argv.
 *
 * WHY. Every secret this tool needs — the three AWS credential parts and, since
 * ROT-7, the base64 DEK — arrives as a command-line flag. Inside a Nitro enclave
 * the process space holds only the signer binary and the kmstool child it
 * spawns, so there is no third party to read /proc/<pid>/cmdline: this is a
 * property to fix, not a live hole. It is worth fixing anyway, because "secrets
 * never appear in argv" is a claim we would like to be able to make plainly.
 *
 * WHY A HEADER, AND WHY PLAIN C. The vendored file that reaches the image is
 * exactly one — `main.c`, overlaid onto the upstream SDK tree before cmake runs
 * (see enclave/Dockerfile). Adding a second translation unit would mean editing
 * upstream's CMakeLists, widening the vendor footprint for no gain. A header of
 * `static` functions compiles into main.c with no build change at all.
 *
 * Plain C with no SDK types on purpose: that is what makes this parser testable
 * OUTSIDE the enclave and outside the SDK. The binary itself cannot be run on a
 * normal host — `aws_nitro_enclaves_library_init` and the entropy seed run
 * before argument parsing and abort — so without this separation the parsing
 * logic would ship having never executed anywhere. It is now covered by
 * scripts/test_secrets_stdin.py, which compiles this header standalone.
 *
 * THE FORMAT is line-oriented `KEY=VALUE`, terminated by EOF:
 *
 *     AWS_ACCESS_KEY_ID=AKIA...
 *     AWS_SECRET_ACCESS_KEY=...
 *     AWS_SESSION_TOKEN=...
 *     PLAINTEXT_B64=ZGVr            (encrypt only; omitted otherwise)
 *
 * Order-independent, self-describing, and every value ends at the newline — no
 * length prefixes to get wrong. None of the four values can legally contain a
 * newline (AWS credentials and base64 are newline-free), so the delimiter is
 * unambiguous by construction rather than by convention.
 *
 * FAIL CLOSED, always. Unknown key, duplicate key, missing '=', a line over the
 * cap, more lines than expected, or a value over the cap — all are errors that
 * abort the read. A truncated stream simply leaves a key absent, and the caller
 * refuses to run without it, so a half-delivered credential can never be used
 * as if it were whole.
 */

#ifndef KMSTOOL_SECRETS_STDIN_H
#define KMSTOOL_SECRETS_STDIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Generous vs. reality: AWS session tokens run to ~2 KB, a base64 32-byte DEK is
 * 44 bytes. 8 KB per value means a malformed stream cannot make us allocate
 * without bound, and still leaves an order of magnitude of headroom. */
#define KMSTOOL_STDIN_MAX_VALUE 8192
/* Four keys today. The cap is on LINES so a stream of blank or repeated lines
 * cannot spin: eight is four keys plus slack, and anything beyond it is a
 * malformed stream, not a generous caller. */
#define KMSTOOL_STDIN_MAX_LINES 8

enum kmstool_stdin_status {
    KMSTOOL_STDIN_OK = 0,
    KMSTOOL_STDIN_ERR_LINE_TOO_LONG,
    KMSTOOL_STDIN_ERR_TOO_MANY_LINES,
    KMSTOOL_STDIN_ERR_NO_EQUALS,
    KMSTOOL_STDIN_ERR_UNKNOWN_KEY,
    KMSTOOL_STDIN_ERR_DUPLICATE_KEY,
    KMSTOOL_STDIN_ERR_EMPTY_VALUE,
    KMSTOOL_STDIN_ERR_OOM,
    KMSTOOL_STDIN_ERR_READ
};

struct kmstool_stdin_secrets {
    char *access_key_id;     /* NULL when the key was absent */
    char *secret_access_key;
    char *session_token;
    char *plaintext_b64;
};

/* Wipe then free. `memset` through a volatile pointer so the compiler may not
 * elide the store on a buffer that is about to be freed — the whole point of
 * moving secrets off argv is undone if they linger in the heap instead. */
static void kmstool_secure_free(char **p) {
    if (p == NULL || *p == NULL) {
        return;
    }
    volatile char *v = (volatile char *)*p;
    size_t n = strlen(*p);
    while (n-- > 0) {
        v[n] = 0;
    }
    free(*p);
    *p = NULL;
}

static void kmstool_stdin_secrets_clean_up(struct kmstool_stdin_secrets *s) {
    if (s == NULL) {
        return;
    }
    kmstool_secure_free(&s->access_key_id);
    kmstool_secure_free(&s->secret_access_key);
    kmstool_secure_free(&s->session_token);
    kmstool_secure_free(&s->plaintext_b64);
}

static const char *kmstool_stdin_strerror(enum kmstool_stdin_status st) {
    switch (st) {
        case KMSTOOL_STDIN_OK:
            return "ok";
        case KMSTOOL_STDIN_ERR_LINE_TOO_LONG:
            return "a line exceeded the value cap";
        case KMSTOOL_STDIN_ERR_TOO_MANY_LINES:
            return "too many lines";
        case KMSTOOL_STDIN_ERR_NO_EQUALS:
            return "line has no '='";
        case KMSTOOL_STDIN_ERR_UNKNOWN_KEY:
            return "unknown key";
        case KMSTOOL_STDIN_ERR_DUPLICATE_KEY:
            return "duplicate key";
        case KMSTOOL_STDIN_ERR_EMPTY_VALUE:
            return "empty value";
        case KMSTOOL_STDIN_ERR_OOM:
            return "out of memory";
        case KMSTOOL_STDIN_ERR_READ:
            return "read error";
    }
    return "unknown error";
}

/* Assign into the right slot. Returns 0 on success, or a duplicate/unknown-key
 * status. Deliberately an exact-match table rather than a prefix compare: a
 * prefix would let `AWS_SESSION_TOKEN_EXTRA=` land in a real slot. */
static enum kmstool_stdin_status kmstool_stdin_assign(
    struct kmstool_stdin_secrets *out, const char *key, char *value) {
    char **slot = NULL;
    if (strcmp(key, "AWS_ACCESS_KEY_ID") == 0) {
        slot = &out->access_key_id;
    } else if (strcmp(key, "AWS_SECRET_ACCESS_KEY") == 0) {
        slot = &out->secret_access_key;
    } else if (strcmp(key, "AWS_SESSION_TOKEN") == 0) {
        slot = &out->session_token;
    } else if (strcmp(key, "PLAINTEXT_B64") == 0) {
        slot = &out->plaintext_b64;
    } else {
        return KMSTOOL_STDIN_ERR_UNKNOWN_KEY;
    }
    if (*slot != NULL) {
        /* A second value for the same key is never a caller being helpful — it
         * is a stream someone spliced. Refusing beats guessing which one wins. */
        return KMSTOOL_STDIN_ERR_DUPLICATE_KEY;
    }
    *slot = value;
    return KMSTOOL_STDIN_OK;
}

/* Read the whole stream. On ANY error the partially-filled struct is wiped
 * before returning, so a caller that ignores the status cannot find a usable
 * half-credential in it. */
static enum kmstool_stdin_status kmstool_stdin_read_secrets(
    FILE *in, struct kmstool_stdin_secrets *out) {
    memset(out, 0, sizeof(*out));

    /* +2: one for a trailing newline, one to notice a line that is exactly one
     * byte too long instead of silently splitting it into two lines. */
    char line[KMSTOOL_STDIN_MAX_VALUE + 2];
    int lines = 0;

    while (fgets(line, (int)sizeof(line), in) != NULL) {
        if (++lines > KMSTOOL_STDIN_MAX_LINES) {
            kmstool_stdin_secrets_clean_up(out);
            return KMSTOOL_STDIN_ERR_TOO_MANY_LINES;
        }
        size_t len = strlen(line);
        int had_newline = (len > 0 && line[len - 1] == '\n');
        if (had_newline) {
            line[--len] = '\0';
        } else if (len == sizeof(line) - 1) {
            /* Filled the buffer with no newline: the line is longer than the cap
             * and the rest would be read as a fresh line — which is how a long
             * value turns into a bogus key. Refuse. */
            kmstool_stdin_secrets_clean_up(out);
            return KMSTOOL_STDIN_ERR_LINE_TOO_LONG;
        }
        /* Tolerate CR from a CRLF writer at the END only; an embedded CR stays,
         * so a malformed value is rejected downstream rather than repaired into
         * a different one. */
        if (len > 0 && line[len - 1] == '\r') {
            line[--len] = '\0';
        }
        if (len == 0) {
            continue; /* blank line: ignorable framing, not data */
        }

        char *eq = strchr(line, '=');
        if (eq == NULL) {
            kmstool_stdin_secrets_clean_up(out);
            return KMSTOOL_STDIN_ERR_NO_EQUALS;
        }
        *eq = '\0';
        const char *key = line;
        const char *val = eq + 1;
        if (*val == '\0') {
            /* An empty secret is never meaningful and would otherwise satisfy
             * the "was it provided" check downstream. */
            kmstool_stdin_secrets_clean_up(out);
            return KMSTOOL_STDIN_ERR_EMPTY_VALUE;
        }
        if (strlen(val) > KMSTOOL_STDIN_MAX_VALUE) {
            kmstool_stdin_secrets_clean_up(out);
            return KMSTOOL_STDIN_ERR_LINE_TOO_LONG;
        }

        /* malloc+memcpy, NOT strdup: `strdup` is POSIX, not ISO C99, so under
         * `-std=c99` on glibc it is not declared and the call silently becomes
         * an implicit int-returning function — a pointer built from an int.
         * Caught by CI on 2026-08-09; the Mac toolchain declares it regardless
         * and hid the defect locally. A vendored header should not depend on
         * which visibility macros its includer happens to have set. */
        size_t val_len = strlen(val);
        char *copy = (char *)malloc(val_len + 1);
        if (copy != NULL) {
            memcpy(copy, val, val_len + 1);
        }
        if (copy == NULL) {
            kmstool_stdin_secrets_clean_up(out);
            return KMSTOOL_STDIN_ERR_OOM;
        }
        enum kmstool_stdin_status st = kmstool_stdin_assign(out, key, copy);
        if (st != KMSTOOL_STDIN_OK) {
            kmstool_secure_free(&copy);
            kmstool_stdin_secrets_clean_up(out);
            return st;
        }
    }

    if (ferror(in)) {
        kmstool_stdin_secrets_clean_up(out);
        return KMSTOOL_STDIN_ERR_READ;
    }
    return KMSTOOL_STDIN_OK;
}

#endif /* KMSTOOL_SECRETS_STDIN_H */
