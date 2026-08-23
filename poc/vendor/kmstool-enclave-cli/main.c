#include <aws/nitro_enclaves/kms.h>
#include <aws/nitro_enclaves/nitro_enclaves.h>

#include <aws/common/command_line_parser.h>
#include <aws/common/encoding.h>
#include <aws/common/hash_table.h>
#include <aws/common/logging.h>
#include <aws/common/string.h>

#include <json-c/json.h>

/* ROT-8: secrets via stdin. Header-only, plain C, no SDK types — see the file
 * for why it is a header and how it is tested outside the enclave. */
#include "secrets_stdin.h"

#include <linux/vm_sockets.h>
#include <sys/socket.h>

#include <errno.h>
#include <unistd.h>

#define DEFAULT_PROXY_PORT  8000
#define DEFAULT_REGION      "us-east-1"
#define DEFAULT_PARENT_CID  "3"

#define DECRYPT_CMD "decrypt"
#define GENKEY_CMD  "genkey"
#define GENRANDOM_CMD  "genrandom"
/* ROT-7: `encrypt` wraps an enclave-generated DEK under the KMS key WITH an
 * EncryptionContext. It exists because `genkey` CANNOT carry a context: the
 * SDK ships no `aws_kms_generate_data_key_blocking_with_context` and no
 * `..._from_request` transport for GenerateDataKey — verified against upstream
 * `main`, not just our pinned v0.4.5. `aws_kms_encrypt_blocking_with_context`
 * DOES exist upstream, so this route needs no SDK patch at all and keeps the
 * "SDK built unchanged from upstream" property this vendor tree protects. */
#define ENCRYPT_CMD "encrypt"

#define AES_256_ARG "AES-256"
#define AES_128_ARG "AES-128"

#define MAX_SUB_COMMAND_LENGTH sizeof(GENRANDOM_CMD)
#define MAX_KEY_SPEC_LENGTH sizeof(AES_256_ARG)

/* Initial size hint for the EncryptionContext hash table. */
#define DEFAULT_ENCRYPTION_CONTEXT_ELEMENT_NUM 10

enum status {
    STATUS_OK,
    STATUS_ERR,
};

#define fail_on(cond, msg)                                                                                             \
    if (cond) {                                                                                                        \
        if (msg != NULL) {                                                                                             \
            fprintf(stderr, "%s\n", msg);                                                                              \
        }                                                                                                              \
        return AWS_OP_ERR;                                                                                             \
    }

struct app_ctx {
    /* Allocator to use for memory allocations. */
    struct aws_allocator *allocator;
    /* KMS region to use. */
    const struct aws_string *region;
    /* vsock port on which to open service. */
    uint32_t port;
    /* vsock port on which vsock-proxy is available in parent. */
    uint32_t proxy_port;

    /* ROT-8: secrets arrived on stdin rather than argv. Kept on the context so
     * the required-argument checks can tell "absent" from "supplied elsewhere"
     * without re-reading the stream. */
    bool secrets_from_stdin;

    /* KMS credentials */
    const struct aws_string *aws_access_key_id;
    const struct aws_string *aws_secret_access_key;
    const struct aws_string *aws_session_token;

    /* Data parameters */
    const struct aws_string *ciphertext_b64;
    const struct aws_string *encryption_algorithm;
    const struct aws_string *key_id;
    enum aws_key_spec key_spec;

    /* EncryptionContext for decrypt — populated from repeated
     * `--encryption-context KEY=VALUE` args. Per AWS KMS, decrypt fails
     * unless this exactly matches the context supplied at Encrypt time. */
    struct aws_hash_table encryption_context;

    /* GenRandom parameters */
    uint32_t length;

    /* ENCRYPT parameter (ROT-7): base64 plaintext to wrap. Held as a plain
     * `aws_string` like every other arg; the DEK it carries is short-lived and
     * the process exits immediately after printing the ciphertext. The
     * PLAINTEXT never leaves this process — only `CIPHERTEXT:` is printed. */
    const struct aws_string *plaintext_b64;
};

/*
 * Function to print the different commands
 */
static void print_commands(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli [command]\n");
    fprintf(stderr, "\n Commands: \n\n");
    fprintf(stderr, "    decrypt: Decrypt a given ciphertext blob.\n");
    fprintf(stderr, "    genkey: Generate a datakey from KMS encrypted with the given key id.\n");
    fprintf(stderr, "    genrandom: Generate a random byte string from KMS.\n");
    fprintf(stderr, "    encrypt: Encrypt a plaintext under the given key id, with EncryptionContext.\n");
    exit(exit_code);
}

/*
 * Function to print out the argumetns for decrypt
 */
static void s_usage_decrypt(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli decrypt [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --ciphertext CIPHERTEXT: base64-encoded ciphertext that need to decrypt\n");
    fprintf(stderr, "    --key-id KEY_ID: decrypt key id (for symmetric keys, is optional)\n");
    fprintf(stderr, "    --encryption-algorithm ENCRYPTION_ALGORITHM: encryption algorithm for ciphertext\n");
    fprintf(stderr, "    --encryption-context NAME=VALUE: key-value pair to add to the request's "
                    "EncryptionContext. Repeat the flag once per pair. Must exactly match the "
                    "context supplied at Encrypt time, or KMS rejects the request.\n");
    exit(exit_code);
}

/*
 * Function to print out the arguments for genkey
 */
static void s_usage_genkey(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli genkey [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --key-id KEY_ID: key id\n");
    fprintf(stderr, "    --key-spec KEY_SPEC: The key spec used to create the key (AES-256 or AES-128).\n");
    fprintf(stderr, "\n NOTE: genkey does NOT accept --encryption-context and never will: the SDK\n");
    fprintf(stderr, "       exposes no context-aware GenerateDataKey. Passing it is a hard error on\n");
    fprintf(stderr, "       purpose — silently dropping it would produce a data key wrapped WITHOUT\n");
    fprintf(stderr, "       context, which the context-pinned read path can never unwrap. Use the\n");
    fprintf(stderr, "       `encrypt` subcommand to wrap an enclave-generated DEK with a context.\n");
    exit(exit_code);
}

/*
 * Function to print out the arguments for encrypt (ROT-7)
 */
static void s_usage_encrypt(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli encrypt [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --key-id KEY_ID: key id to encrypt under\n");
    fprintf(stderr, "    --plaintext PLAINTEXT: base64-encoded plaintext to encrypt\n");
    fprintf(stderr, "    --encryption-context NAME=VALUE: key-value pair to add to the request's "
                    "EncryptionContext. Repeat the flag once per pair. REQUIRED — see below.\n");
    fprintf(stderr, "\n NOTE: at least one --encryption-context pair is REQUIRED. A context-less\n");
    fprintf(stderr, "       wrap would be silently unusable by the context-pinned read path, so\n");
    fprintf(stderr, "       this subcommand fails closed rather than defaulting to no context.\n");
    exit(exit_code);
}

/*
 * Function to print out the arguments for genrandom
 */
static void s_usage_genrandom(int exit_code) {
    fprintf(stderr, "usage: kmstool_enclave_cli genrandom [options]\n");
    fprintf(stderr, "\n Options: \n\n");
    fprintf(stderr, "    --help: Displays this message and exits\n");
    fprintf(stderr, "    --region REGION: AWS region to use for KMS. Default: 'us-east-1'\n");
    fprintf(stderr, "    --proxy-port PORT: Connect to KMS proxy on PORT. Default: 8000\n");
    fprintf(stderr, "    --aws-access-key-id ACCESS_KEY_ID: AWS access key ID\n");
    fprintf(stderr, "    --aws-secret-access-key SECRET_ACCESS_KEY: AWS secret access key\n");
    fprintf(stderr, "    --aws-session-token SESSION_TOKEN: Session token associated with the access key ID\n");
    fprintf(stderr, "    --length NO_OF_BYTES: The length of the random byte string\n");
    exit(exit_code);
}

/* Command line options */
static struct aws_cli_option s_long_options[] = {
    {"region", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'r'},
    {"proxy-port", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'x'},
    {"aws-access-key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'k'},
    {"aws-secret-access-key", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 's'},
    {"aws-session-token", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 't'},
    {"ciphertext", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'c'},
    {"key-id", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'K'},
    {"key-spec", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'p'},
    {"encryption-algorithm", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'a'},
    {"encryption-context", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'e'},
    {"length", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'l'},
    /* ROT-7: `encrypt` input. Short code 'P' (capital) — 'p' is already
     * --key-spec and the codes are a single flat namespace shared by all
     * subcommands. */
    {"plaintext", AWS_CLI_OPTIONS_REQUIRED_ARGUMENT, NULL, 'P'},
    /* ROT-8: read the four secret-bearing values from stdin instead of argv.
     * No argument of its own — the secrets are the payload, not the flag. */
    {"secrets-from-stdin", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'S'},
    {"help", AWS_CLI_OPTIONS_NO_ARGUMENT, NULL, 'h'},
    {NULL, 0, NULL, 0},
};

/*
 * Parse a single `--encryption-context KEY=VALUE` argument into the
 * caller's hash table. Mirrors the equivalent helper added upstream
 * in kmstool-instance (aws/aws-nitro-enclaves-sdk-c, commits 5c535bc /
 * 1f0349e on feature/pass-encryption-context-as-cli-args).
 *
 * If the argument is malformed (no `=` separator) the pair is
 * silently skipped; callers are expected to validate context coverage
 * via the count after parsing.
 */
static void s_parse_encryption_context_arg(
    struct aws_allocator *allocator,
    struct aws_hash_table *map,
    const char *arg) {
    size_t separator_pos = 0;
    while (arg[separator_pos] != '\0' && arg[separator_pos] != '=') {
        ++separator_pos;
    }

    if (arg[separator_pos] == '\0') {
        return;
    }

    struct aws_string *map_key = aws_string_new_from_array(allocator, (const uint8_t *)arg, separator_pos);
    if (map_key == NULL) {
        return;
    }

    struct aws_string *map_value = aws_string_new_from_c_str(allocator, &arg[separator_pos + 1]);
    if (map_value == NULL) {
        aws_string_destroy(map_key);
        return;
    }

    /* Gemini PR #68 round-1 MED: when key already exists, aws_hash_table_put
     * keeps the old key and replaces the value — the new map_key is not
     * stored and would leak without explicit destroy. We check was_created
     * and free map_key in that case. (Upstream kmstool-instance has the
     * same bug; we deviate from upstream verbatim here to ship clean code.) */
    int was_created = 0;
    if (aws_hash_table_put(map, map_key, map_value, &was_created) != AWS_OP_SUCCESS) {
        aws_string_destroy(map_key);
        aws_string_destroy(map_value);
    } else if (!was_created) {
        aws_string_destroy(map_key);
    }
}

/* Defined near the bottom, beside `main`. Forward-declared because every
 * validation failure in `s_parse_options` has to wipe the secrets before it
 * exits — see the corrected block comment at `cleanup_sdk`. */
static void s_app_ctx_secure_clean_up(struct app_ctx *ctx);

/*
 * Function to parse the common command line arguments.
 *
 * @param[in]  argc: number of arguments
 * @param[in]  argv: array of passed in arguments
 * @param[in]  subcommand: sub-command being called
 * @param[out] app_ctx: struct to store all of the arguments
 */
static void s_parse_options(int argc, char **argv, const char *subcommand, struct app_ctx *ctx) {
    ctx->proxy_port = DEFAULT_PROXY_PORT;
    ctx->region = NULL;
    ctx->aws_access_key_id = NULL;
    ctx->aws_secret_access_key = NULL;
    ctx->aws_session_token = NULL;
    ctx->ciphertext_b64 = NULL;
    ctx->key_id = NULL;
    ctx->key_spec = -1;
    ctx->encryption_algorithm = NULL;
    ctx->length = -1;
    ctx->plaintext_b64 = NULL;

    aws_cli_optind = 2;
    while (true) {
        int option_index = 0;

        /* ROT-7: `P:` added for --plaintext (encrypt). */
        int c = aws_cli_getopt_long(argc, argv, "r:x:k:s:t:c:K:p:a:e:l:P:Sh", s_long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                break;
            case 'r':
                ctx->region = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'x':          
                ctx->proxy_port = atoi(aws_cli_optarg);
                break;
            case 'S':
                ctx->secrets_from_stdin = true;
                break;
            case 'k':
                ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 's':
                ctx->aws_secret_access_key = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 't':
                ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                break;
            case 'h':
                if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_decrypt(1);
                else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_genkey(1);
                else if (strncmp(subcommand, GENRANDOM_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_genrandom(1);
                else if (strncmp(subcommand, ENCRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0)
                    s_usage_encrypt(1);
                break;
            default:
                if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
                    switch (c) {
                        case 'c':
                            ctx->ciphertext_b64 = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                         case 'a':
                            ctx->encryption_algorithm = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                         case 'K':
                            ctx->key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                         case 'e':
                            s_parse_encryption_context_arg(ctx->allocator, &ctx->encryption_context, aws_cli_optarg);
                            break;
                        default:
                            fprintf(stderr, "Unknown option: %s\n", aws_cli_optarg);
                            s_usage_decrypt(1);
                    }
                } else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
                    switch(c) {
                        case 'K':
                            ctx->key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                        case 'p':
                            if (strncmp(aws_cli_optarg, AES_256_ARG, MAX_KEY_SPEC_LENGTH) == 0) {
                                ctx->key_spec = AWS_KS_AES_256;
                            } else if (strncmp(aws_cli_optarg, AES_128_ARG, MAX_KEY_SPEC_LENGTH) == 0) {
                                ctx->key_spec = AWS_KS_AES_128;
                            } else {
                                fprintf(stderr, "Unknown key spec: %s\n", aws_cli_optarg);
                                s_usage_genkey(1);
                            }
                            break;
                        default:
                            /* Gemini PR #68 round-2 (manual relay): upstream
                             * silently ignored unknown flags on genkey instead
                             * of usage-erroring like decrypt does. Adds parity. */
                            fprintf(stderr, "Unknown option: %s\n", aws_cli_optarg);
                            s_usage_genkey(1);
                    }
                } else if (strncmp(subcommand, ENCRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
                    /* ROT-7. Mirrors the decrypt branch: this is the ONLY other
                     * subcommand that carries an EncryptionContext, and unlike
                     * decrypt the context here is mandatory (checked after the
                     * parse loop, so a missing flag and a malformed one give the
                     * same fail-closed result). */
                    switch(c) {
                        case 'K':
                            ctx->key_id = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                        case 'P':
                            ctx->plaintext_b64 = aws_string_new_from_c_str(ctx->allocator, aws_cli_optarg);
                            break;
                        case 'e':
                            s_parse_encryption_context_arg(ctx->allocator, &ctx->encryption_context, aws_cli_optarg);
                            break;
                        default:
                            fprintf(stderr, "Unknown option: %s\n", aws_cli_optarg);
                            s_usage_encrypt(1);
                    }
                } else if (strncmp(subcommand, GENRANDOM_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
                    switch(c) {
                        case 'l':
                            ctx->length = atoi(aws_cli_optarg);
                            break;
                        default:
                            /* Gemini PR #68 round-2 (manual relay): same fix
                             * as genkey above — usage-error on unknown flag. */
                            fprintf(stderr, "Unknown option: %s\n", aws_cli_optarg);
                            s_usage_genrandom(1);
                    }
                }
        }
    }

    /* ─── ROT-8: pull the secrets off stdin ──────────────────────────────────
     *
     * Runs AFTER the option loop so `--secrets-from-stdin` has been seen, and
     * BEFORE the required-argument checks so a value delivered on stdin
     * satisfies them exactly as a flag would.
     *
     * MIXING IS REFUSED, not merged. If a secret arrives both ways we cannot
     * know which the caller meant, and picking one silently is how a rotation
     * ends up signing with a credential nobody intended. Refusing costs one
     * clear error; guessing costs an investigation.
     */
    if (ctx->secrets_from_stdin) {
        if (ctx->aws_access_key_id != NULL || ctx->aws_secret_access_key != NULL ||
            ctx->aws_session_token != NULL || ctx->plaintext_b64 != NULL) {
            fprintf(stderr,
                    "--secrets-from-stdin was given together with a secret flag "
                    "(--aws-access-key-id / --aws-secret-access-key / "
                    "--aws-session-token / --plaintext). Refusing to guess which "
                    "one you meant: pass the secrets on stdin only.\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }
        struct kmstool_stdin_secrets secrets;
        enum kmstool_stdin_status st = kmstool_stdin_read_secrets(stdin, &secrets);
        if (st != KMSTOOL_STDIN_OK) {
            /* The message names the SHAPE problem and never the content — a
             * parse error must not become a way to echo a secret into a log. */
            fprintf(stderr, "--secrets-from-stdin: %s\n", kmstool_stdin_strerror(st));
            kmstool_stdin_secrets_clean_up(&secrets);
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }
        if (secrets.access_key_id != NULL) {
            ctx->aws_access_key_id = aws_string_new_from_c_str(ctx->allocator, secrets.access_key_id);
        }
        if (secrets.secret_access_key != NULL) {
            ctx->aws_secret_access_key =
                aws_string_new_from_c_str(ctx->allocator, secrets.secret_access_key);
        }
        if (secrets.session_token != NULL) {
            ctx->aws_session_token = aws_string_new_from_c_str(ctx->allocator, secrets.session_token);
        }
        if (secrets.plaintext_b64 != NULL) {
            ctx->plaintext_b64 = aws_string_new_from_c_str(ctx->allocator, secrets.plaintext_b64);
        }
        /* Wipe the intermediate copies immediately: from here the values live
         * only in the aws_string fields, which are wiped at exit (see
         * s_app_ctx_secure_clean_up). Two copies of a secret are one more than
         * necessary and the extra one has no owner. */
        kmstool_stdin_secrets_clean_up(&secrets);
    }

    /* Check if AWS access key ID is set */
    if (ctx->aws_access_key_id == NULL) {
        fprintf(stderr, "--aws-access-key-id must be set\n");
        s_app_ctx_secure_clean_up(ctx);
        exit(1);
    }

    /* Check if AWS secret access key is set */
    if (ctx->aws_secret_access_key == NULL) {
        fprintf(stderr, "--aws-secret-access-key must be set\n");
        s_app_ctx_secure_clean_up(ctx);
        exit(1);
    }

    /* Check if AWS session token is set */
    if (ctx->aws_session_token == NULL) {
        fprintf(stderr, "--aws-session-token must be set\n");
        s_app_ctx_secure_clean_up(ctx);
        exit(1);
    }

    /* Set default AWS region if not specified */
    if (ctx->region == NULL) {
        ctx->region = aws_string_new_from_c_str(ctx->allocator, DEFAULT_REGION);
    }

    if (strncmp(subcommand, ENCRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* ROT-7. Key id is mandatory here (unlike decrypt, where symmetric
         * ciphertext carries it). */
        if (ctx->key_id == NULL) {
            fprintf(stderr, "--key-id must be set\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }
        if (ctx->plaintext_b64 == NULL) {
            fprintf(stderr, "--plaintext must be set\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }
        /* FAIL CLOSED on an empty context. This is the whole reason the
         * subcommand exists: a wrap without context produces a ciphertext the
         * context-pinned read path can never open, and the failure would only
         * surface at the first real signature — long after provisioning
         * "succeeded". Defaulting to no-context here would rebuild exactly the
         * silent-invalid-key trap that genkey's hard-fail saved us from. */
        if (aws_hash_table_get_entry_count(&ctx->encryption_context) == 0) {
            fprintf(stderr, "--encryption-context must be set at least once\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }

    } else if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* Check if ciphertext is set */
        if (ctx->ciphertext_b64 == NULL) {
            fprintf(stderr, "--ciphertext must be set\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }

    } else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* Check if the key id is set */
        if (ctx->key_id == NULL) {
            fprintf(stderr, "--key-id must be set\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }

        /* Check if key spec is set */
        if (ctx->key_spec == -1) {
            fprintf(stderr, "--key-spec must be set\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }
    } else if (strncmp(subcommand, GENRANDOM_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* Check if the length is set */
        if (ctx->length == -1) {
            fprintf(stderr, "--length must be set\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }

        /* Check if the length greater than 0 (KMS limit) */
        if (ctx->length <= 0) {
            fprintf(stderr, "--length must be greater than 0\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }

        /* Check if the length smaller or equal to 1024 (KMS limit) */
        if (ctx->length > 1024) {
            fprintf(stderr, "--length must be smaller or equal to 1024\n");
            s_app_ctx_secure_clean_up(ctx);
            exit(1);
        }
    }
}

/*
 * Function to initialize the kms client with the provided aws credentials
 *
 * @param[in]  app_ctx: place where all of the credentials are currently stored
 * @param[out] credentials: location to store the aws credentials
 * @param[out] client: location to store new kms client
 */
static void init_kms_client(struct app_ctx *app_ctx, struct aws_credentials **credentials, struct aws_nitro_enclaves_kms_client **client) {
    /* Parent is always on CID 3 */
    struct aws_socket_endpoint endpoint = {.address = DEFAULT_PARENT_CID, .port = app_ctx->proxy_port};
    struct aws_nitro_enclaves_kms_client_configuration configuration = {
        .allocator = app_ctx->allocator, .endpoint = &endpoint, .domain = AWS_SOCKET_VSOCK, .region = app_ctx->region};

    /* Sets the AWS credentials and creates a KMS client with them. */
    struct aws_credentials *new_credentials = aws_credentials_new(
        app_ctx->allocator,
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_access_key_id->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_secret_access_key->bytes),
        aws_byte_cursor_from_c_str((const char *)app_ctx->aws_session_token->bytes),
        UINT64_MAX);

    /* If credentials or client already exists, replace them. */
    if (*credentials != NULL) {
        aws_nitro_enclaves_kms_client_destroy(*client);
        aws_credentials_release(*credentials);
    }

    *credentials = new_credentials;
    configuration.credentials = new_credentials;
    *client = aws_nitro_enclaves_kms_client_new(&configuration);
}

/*
 * Function to encode a string in base64 for printing
 *
 * @param[in]  app_ctx: contains the allocator required for memory management
 * @param[in]  text: pointer to where the original text is stored
 * @param[out] text_b64: pointer to where the encoded string should be stored
 */ 
static int encode_b64(struct app_ctx *app_ctx, struct aws_byte_buf *text, struct aws_byte_buf *text_b64) {
    ssize_t rc = 0;
    size_t text_b64_len;

    /* CodeRabbit PR #68 round-3 HIGH: zero-init the out-buffer up-front
     * so callers can unconditionally `aws_byte_buf_clean_up` it on every
     * exit path. Upstream's `fail_on` early-return on
     * `aws_byte_buf_init` failure left `*text_b64` in indeterminate
     * state, and on `aws_base64_encode` failure leaked the freshly-
     * init'd buffer. For an encode of plaintext output, that residue
     * could carry partial plaintext bytes — wipe before returning the
     * error so the caller sees a clean zero-state on failure. */
    AWS_ZERO_STRUCT(*text_b64);

    struct aws_byte_cursor text_cursor = aws_byte_cursor_from_buf(text);
    aws_base64_compute_encoded_len(text->len, &text_b64_len);
    rc = aws_byte_buf_init(text_b64, app_ctx->allocator, text_b64_len + 1);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Memory allocation error\n");
        return AWS_OP_ERR;
    }
    rc = aws_base64_encode(&text_cursor, text_b64);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Base64 encoding error\n");
        aws_byte_buf_clean_up(text_b64);
        return AWS_OP_ERR;
    }
    aws_byte_buf_append_null_terminator(text_b64);

    return AWS_OP_SUCCESS;
}

/*
 * Build a JSON object representation of the EncryptionContext hash
 * table for inclusion in a KMS Decrypt request. The SDK's
 * `aws_kms_decrypt_blocking_with_context` API expects a JSON string.
 *
 * Returns NULL on allocation failure; otherwise caller takes ownership
 * of the returned json_object (and must `json_object_put` it).
 *
 * Mirrors the equivalent helper added upstream in kmstool-instance
 * (aws/aws-nitro-enclaves-sdk-c, commits 5c535bc / 1f0349e).
 */
static struct json_object *s_encryption_context_to_json(struct aws_hash_table *context) {
    AWS_PRECONDITION(context);

    struct json_object *json_context = json_object_new_object();
    if (json_context == NULL) {
        return NULL;
    }

    for (struct aws_hash_iter iter = aws_hash_iter_begin(context);
         !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        const struct aws_string *map_key = iter.element.key;
        const struct aws_string *map_value = iter.element.value;

        struct json_object *elem = json_object_new_string(aws_string_c_str(map_value));
        if (elem == NULL) {
            goto cleanup;
        }

        if (json_object_object_add(json_context, aws_string_c_str(map_key), elem) < 0) {
            json_object_put(elem);
            goto cleanup;
        }
    }

    return json_context;

cleanup:
    json_object_put(json_context);
    return NULL;
}

/*
 * Function to decrypt a given ciphertext with attestation.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] ciphertext_decrypted_b64: Byte buffer where the decrypted ciphertext will be stored
 */
static int decrypt(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_decrypted_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* CodeRabbit PR #68 round-3: zero-init both byte_buf locals so the
     * `cleanup:` label can call `aws_byte_buf_clean_up` unconditionally
     * without UB even when goto fires before `aws_byte_buf_init` /
     * `aws_kms_decrypt_blocking_with_context` write to them. AWS aws-c-common
     * documents `aws_byte_buf_clean_up` on a zeroed buffer as a safe no-op. */
    struct aws_byte_buf ciphertext = { 0 };
    struct aws_byte_buf ciphertext_decrypted = { 0 };
    struct aws_string *encryption_context_str = NULL;
    struct json_object *encryption_context_json = NULL;

    init_kms_client(app_ctx, &credentials, &client);

    /* Get decode base64 string into bytes.
     * CodeRabbit PR #68 round-3 HIGH: round-2 left these three early-paths
     * using upstream's `fail_on` macro which `return`s without cleanup,
     * leaking `client` + `credentials` (and `ciphertext` after init).
     * All three converted to `goto cleanup`. */
    size_t ciphertext_len;
    struct aws_byte_cursor ciphertext_b64 = aws_byte_cursor_from_c_str((const char *)app_ctx->ciphertext_b64->bytes);
    rc = aws_base64_compute_decoded_len(&ciphertext_b64, &ciphertext_len);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Ciphertext not a base64 string\n");
        goto cleanup;
    }
    rc = aws_byte_buf_init(&ciphertext, app_ctx->allocator, ciphertext_len);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }
    rc = aws_base64_decode(&ciphertext_b64, &ciphertext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Ciphertext not a base64 string\n");
        goto cleanup;
    }

    /* Build the EncryptionContext JSON string (if any context pairs were supplied)
     * and call the with_context variant of the decrypt API. When the hash table
     * is empty we pass NULL, falling back to the legacy no-context behavior. */

    if (aws_hash_table_get_entry_count(&app_ctx->encryption_context) != 0) {
        encryption_context_json = s_encryption_context_to_json(&app_ctx->encryption_context);
        if (encryption_context_json == NULL) {
            fprintf(stderr, "Could not build EncryptionContext JSON\n");
            rc = AWS_OP_ERR;
            goto cleanup;
        }
        const char *json_str = json_object_to_json_string_ext(encryption_context_json, JSON_C_TO_STRING_PLAIN);
        if (json_str == NULL) {
            fprintf(stderr, "Could not serialize EncryptionContext JSON\n");
            rc = AWS_OP_ERR;
            goto cleanup;
        }
        /* Order matters: copy `json_str` (which points INTO
         * encryption_context_json's owned buffer) BEFORE `json_object_put`,
         * which invalidates that buffer. Then immediately NULL the local so
         * the cleanup label doesn't double-free. The `encryption_context_str
         * == NULL` check below covers the copy-failure case (cleanup label
         * sees encryption_context_json already NULLed). */
        encryption_context_str = aws_string_new_from_c_str(app_ctx->allocator, json_str);
        json_object_put(encryption_context_json);
        encryption_context_json = NULL;
        if (encryption_context_str == NULL) {
            fprintf(stderr, "Could not copy EncryptionContext JSON\n");
            rc = AWS_OP_ERR;
            goto cleanup;
        }
    }

    /* Decrypt the data with KMS. */
    rc = aws_kms_decrypt_blocking_with_context(
        client, app_ctx->key_id, app_ctx->encryption_algorithm,
        &ciphertext, encryption_context_str, &ciphertext_decrypted);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not decrypt ciphertext\n");
        goto cleanup;
    }

    /* Encode plaintext into base64 for printing out the result.
     * `ciphertext_decrypted` is the plaintext output buffer despite the
     * variable name; we encode it as base64 so the parent can read it
     * over stdout. Cleanup of `ciphertext_decrypted` happens in the
     * `cleanup:` label (zero-init'd so safe to clean up unconditionally). */
    rc = encode_b64(app_ctx, &ciphertext_decrypted, ciphertext_decrypted_b64);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encode ciphertext\n");
        goto cleanup;
    }

cleanup:
    /* Single-entry cleanup label — DO NOT goto here twice from one call
     * (locals are not NULLed after release, would cause double-free).
     * Idempotent across allocation states: every guard either NULL-checks
     * the local or relies on aws_byte_buf_clean_up's documented safe
     * no-op behavior on a zeroed buffer.
     *
     * Gemini PR #68 round-2 + CodeRabbit round-3: upstream's `fail_on`
     * macro returned without cleanup, leaking client, credentials,
     * ciphertext, ciphertext_decrypted, encryption_context_str,
     * encryption_context_json on various error paths. All now flow
     * through this label. */
    if (encryption_context_json != NULL) {
        json_object_put(encryption_context_json);
    }
    if (encryption_context_str != NULL) {
        aws_string_destroy(encryption_context_str);
    }
    aws_byte_buf_clean_up(&ciphertext);
    aws_byte_buf_clean_up(&ciphertext_decrypted);
    if (client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
    }
    if (credentials != NULL) {
        aws_credentials_release(credentials);
    }
    return rc;
}

/*
 * ROT-7: encrypt a plaintext under the KMS key WITH an EncryptionContext.
 *
 * Structure is a deliberate mirror of `decrypt()` above — same zero-init,
 * same single-entry `cleanup:` label, same context-to-JSON handling — because
 * that function has been through three review rounds (Gemini #68 r1/r2,
 * CodeRabbit r3) that found real leaks in the upstream `fail_on` pattern.
 * Diverging from its shape here would re-open the same class of bug.
 *
 * Unlike decrypt, the context is NOT optional: `s_parse_options` already
 * refused an empty one, so by the time we get here the hash table is non-empty
 * and the `with_context` call is unconditional. There is deliberately no
 * no-context fallback path.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] ciphertext_b64: Byte buffer where the KMS ciphertext will be stored
 */
static int encrypt_data(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    struct aws_byte_buf plaintext = { 0 };
    struct aws_byte_buf ciphertext = { 0 };
    struct aws_string *encryption_context_str = NULL;
    struct json_object *encryption_context_json = NULL;

    init_kms_client(app_ctx, &credentials, &client);

    /* Decode the base64 plaintext into bytes. */
    size_t plaintext_len;
    /* `from_string`, not `from_c_str`: it takes the length from the
     * `aws_string` instead of scanning for a NUL, so no cast and no strlen
     * (Gemini review on #347). `decrypt()` above still uses the older
     * `from_c_str` form — pre-existing, same result for a base64 argv value,
     * and not this PR's to change. */
    struct aws_byte_cursor plaintext_cur = aws_byte_cursor_from_string(app_ctx->plaintext_b64);
    rc = aws_base64_compute_decoded_len(&plaintext_cur, &plaintext_len);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Plaintext not a base64 string\n");
        goto cleanup;
    }
    rc = aws_byte_buf_init(&plaintext, app_ctx->allocator, plaintext_len);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }
    rc = aws_base64_decode(&plaintext_cur, &plaintext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Plaintext not a base64 string\n");
        goto cleanup;
    }

    /* Build the EncryptionContext JSON. Same ownership dance as decrypt():
     * copy `json_str` BEFORE `json_object_put` invalidates it, then NULL the
     * local so the cleanup label cannot double-free. */
    encryption_context_json = s_encryption_context_to_json(&app_ctx->encryption_context);
    if (encryption_context_json == NULL) {
        fprintf(stderr, "Could not build EncryptionContext JSON\n");
        rc = AWS_OP_ERR;
        goto cleanup;
    }
    const char *json_str = json_object_to_json_string_ext(encryption_context_json, JSON_C_TO_STRING_PLAIN);
    if (json_str == NULL) {
        fprintf(stderr, "Could not serialize EncryptionContext JSON\n");
        rc = AWS_OP_ERR;
        goto cleanup;
    }
    encryption_context_str = aws_string_new_from_c_str(app_ctx->allocator, json_str);
    json_object_put(encryption_context_json);
    encryption_context_json = NULL;
    if (encryption_context_str == NULL) {
        fprintf(stderr, "Could not copy EncryptionContext JSON\n");
        rc = AWS_OP_ERR;
        goto cleanup;
    }

    rc = aws_kms_encrypt_blocking_with_context(
        client, app_ctx->key_id, &plaintext, encryption_context_str, &ciphertext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encrypt plaintext\n");
        goto cleanup;
    }

    rc = encode_b64(app_ctx, &ciphertext, ciphertext_b64);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encode ciphertext\n");
        goto cleanup;
    }

cleanup:
    /* Single-entry cleanup label — see decrypt() for why every error path
     * flows here instead of using upstream's `fail_on`. `plaintext` holds the
     * DEK, so wipe it explicitly rather than only freeing it. */
    if (encryption_context_json != NULL) {
        json_object_put(encryption_context_json);
    }
    if (encryption_context_str != NULL) {
        aws_string_destroy(encryption_context_str);
    }
    /* `clean_up_secure` = secure_zero + clean_up in one call. The name used in
     * the first cut of this function does NOT exist in aws-c-common at our
     * pinned ref, and the EIF build caught it as an undefined reference at LINK
     * time — the Rust side compiles clean and could never have surfaced it.
     * Replacement verified twice: against the pinned upstream header, and
     * against the symbols the already-built binary actually exports. Safe on a
     * zero-initialized buffer: secure_zero guards on `buf->buffer` non-NULL. */
    aws_byte_buf_clean_up_secure(&plaintext);
    aws_byte_buf_clean_up(&ciphertext);
    if (client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
    }
    if (credentials != NULL) {
        aws_credentials_release(credentials);
    }
    return rc;
}

/*
 * Function to generate a data key from KMS with attestation.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] ciphertext_decrypted_b64: Byte buffer where the ciphertext blob will be stored
 * @param[out] plaintext_b64: Byte buffer where the plaintext output will be stored
 */
static int gen_datakey(struct app_ctx *app_ctx, struct aws_byte_buf *ciphertext_b64, struct aws_byte_buf *plaintext_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Zero-init so aws_byte_buf_clean_up is safe in cleanup label if we
     * jump there before aws_kms_generate_data_key_blocking initializes them. */
    struct aws_byte_buf plaintext = { 0 };
    struct aws_byte_buf ciphertext = { 0 };
    int kms_buffers_initialized = 0;

    init_kms_client(app_ctx, &credentials, &client);

    /* Generate data key with KMS. */
    rc = aws_kms_generate_data_key_blocking(client, app_ctx->key_id, app_ctx->key_spec, &plaintext, &ciphertext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not generate data key\n");
        goto cleanup;
    }
    kms_buffers_initialized = 1;

    /* Encode ciphertext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &ciphertext, ciphertext_b64);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encode ciphertext\n");
        goto cleanup;
    }

    /* Encode plaintext into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &plaintext, plaintext_b64);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encode plaintext\n");
        goto cleanup;
    }

cleanup:
    /* Gemini PR #68 round-2 (manual relay): refactor upstream's `fail_on`
     * early-return pattern to centralized cleanup. Leaks plaintext,
     * ciphertext, client, credentials previously occurred on every
     * encode_b64 / kms-call failure. */
    if (kms_buffers_initialized) {
        aws_byte_buf_clean_up(&plaintext);
        aws_byte_buf_clean_up(&ciphertext);
    }
    if (client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
    }
    if (credentials != NULL) {
        aws_credentials_release(credentials);
    }
    return rc;
}

/*
 * Function to generate random bytes from KMS with attestation.
 *
 * @param[in]  app_ctx: Struct that has all of the necessary arguments
 * @param[out] plaintext_b64: Byte buffer where the plaintext random bytes output will be stored
 */
static int gen_random(struct app_ctx *app_ctx, struct aws_byte_buf *plaintext_b64) {
    ssize_t rc = 0;

    struct aws_credentials *credentials = NULL;
    struct aws_nitro_enclaves_kms_client *client = NULL;

    /* Zero-init so aws_byte_buf_clean_up is safe in cleanup label if we
     * jump there before aws_kms_generate_random_blocking initializes it. */
    struct aws_byte_buf plaintext = { 0 };
    int plaintext_initialized = 0;

    init_kms_client(app_ctx, &credentials, &client);

    /* Generate random bytes with KMS. */
    rc = aws_kms_generate_random_blocking(client, app_ctx->length, &plaintext);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not generate random bytes\n");
        goto cleanup;
    }
    plaintext_initialized = 1;

    /* Encode random bytes into base64 for printing out the result. */
    rc = encode_b64(app_ctx, &plaintext, plaintext_b64);
    if (rc != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not encode random bytes\n");
        goto cleanup;
    }

cleanup:
    /* Gemini PR #68 round-2 (manual relay): refactor upstream's `fail_on`
     * early-return pattern to centralized cleanup. Leaks plaintext, client,
     * credentials previously occurred on every encode_b64 / kms-call
     * failure. */
    if (plaintext_initialized) {
        aws_byte_buf_clean_up(&plaintext);
    }
    if (client != NULL) {
        aws_nitro_enclaves_kms_client_destroy(client);
    }
    if (credentials != NULL) {
        aws_credentials_release(credentials);
    }
    return rc;
}

/* ROT-8: wipe the secret-bearing strings before the process exits.
 *
 * Moving secrets off argv is only half the job: until now these four
 * `aws_string`s were never destroyed at all — they lived in the heap until the
 * process died, and a heap that is never wiped is a smaller version of the
 * problem argv was. `aws_string_destroy_secure` zeroes before freeing.
 *
 * Only these four. `region`, `key_id`, `ciphertext_b64` and friends are not
 * secrets, and destroying them here would be churn without a security story. */
static void s_app_ctx_secure_clean_up(struct app_ctx *ctx) {
    if (ctx->aws_access_key_id != NULL) {
        aws_string_destroy_secure((struct aws_string *)ctx->aws_access_key_id);
        ctx->aws_access_key_id = NULL;
    }
    if (ctx->aws_secret_access_key != NULL) {
        aws_string_destroy_secure((struct aws_string *)ctx->aws_secret_access_key);
        ctx->aws_secret_access_key = NULL;
    }
    if (ctx->aws_session_token != NULL) {
        aws_string_destroy_secure((struct aws_string *)ctx->aws_session_token);
        ctx->aws_session_token = NULL;
    }
    if (ctx->plaintext_b64 != NULL) {
        aws_string_destroy_secure((struct aws_string *)ctx->plaintext_b64);
        ctx->plaintext_b64 = NULL;
    }
}

int main(int argc, char **argv) {
    struct app_ctx app_ctx;
    int rc;
    int exit_rc = 0;
    const char *subcommand;

    /* Initialize the SDK */
    aws_nitro_enclaves_library_init(NULL);

    /* Initialize the entropy pool: this is relevant for TLS */
    AWS_ASSERT(aws_nitro_enclaves_library_seed_entropy(1024) == AWS_OP_SUCCESS);

    /* Parse the commandline */
    app_ctx.allocator = aws_nitro_enclaves_get_allocator();

    /* Verifies there are at least two arguments */
    if (argc < 2) {
        print_commands(1);
    }

    subcommand = argv[1];

    /* Optional: Enable logging for aws-c-* libraries */
    struct aws_logger err_logger;
    struct aws_logger_standard_options options = {
        .file = stderr,
        .level = AWS_LL_INFO,
        .filename = NULL,
    };
    aws_logger_init_standard(&err_logger, app_ctx.allocator, &options);
    aws_logger_set(&err_logger);

    /* Initialize the EncryptionContext hash table BEFORE parsing options so
     * the `--encryption-context` parser can populate it. Owns key + value
     * strings; freed by aws_hash_table_clean_up at the cleanup label below.
     * Gemini PR #68 round-1 HIGH: replaced upstream's `fail_on` early-return
     * pattern with explicit if-checks + `goto cleanup` so the hash table
     * always wipes even on subcommand error. (Upstream decrypt/gen_datakey/
     * gen_random still leak via `fail_on` internally — pre-existing, out
     * of scope per dispatch single-purpose rule; documented in PATCH.md.) */
    if (aws_hash_table_init(
            &app_ctx.encryption_context,
            app_ctx.allocator,
            DEFAULT_ENCRYPTION_CONTEXT_ELEMENT_NUM,
            aws_hash_string,
            aws_hash_callback_string_eq,
            aws_hash_callback_string_destroy,
            aws_hash_callback_string_destroy) != AWS_OP_SUCCESS) {
        fprintf(stderr, "Could not initialize encryption context map\n");
        exit_rc = 1;
        goto cleanup_sdk;
    }

    s_parse_options(argc, argv, subcommand, &app_ctx);

    /* CodeRabbit PR #68 round-3 HIGH: subcommand out-buffers are
     * zero-initialized so they're safe to clean up unconditionally even
     * on the error path. `encode_b64` zero-inits its out-param up front
     * before any allocation, but defense-in-depth init here too. */
    if (strncmp(subcommand, DECRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        struct aws_byte_buf ciphertext_decrypted_b64 = { 0 };

        rc = decrypt(&app_ctx, &ciphertext_decrypted_b64);
        if (rc == AWS_OP_SUCCESS) {
            /* Print the base64-encoded plaintext to stdout */
            fprintf(stdout, "PLAINTEXT: %s\n", (const char *)ciphertext_decrypted_b64.buffer);
        } else {
            fprintf(stderr, "Could not decrypt\n");
            exit_rc = 1;
        }
        aws_byte_buf_clean_up(&ciphertext_decrypted_b64);
        if (rc != AWS_OP_SUCCESS) goto cleanup_hash_table;
    } else if (strncmp(subcommand, GENKEY_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        struct aws_byte_buf ciphertext_b64 = { 0 };
        struct aws_byte_buf plaintext_b64 = { 0 };

        rc = gen_datakey(&app_ctx, &ciphertext_b64, &plaintext_b64);
        if (rc == AWS_OP_SUCCESS) {
            /* Print the base64-encoded ciphertext and plaintext to stdout */
            fprintf(stdout, "CIPHERTEXT: %s\n", (const char *)ciphertext_b64.buffer);
            fprintf(stdout, "PLAINTEXT: %s\n", (const char *)plaintext_b64.buffer);
        } else {
            fprintf(stderr, "Could not generate data key\n");
            exit_rc = 1;
        }
        aws_byte_buf_clean_up(&ciphertext_b64);
        aws_byte_buf_clean_up(&plaintext_b64);
        if (rc != AWS_OP_SUCCESS) goto cleanup_hash_table;
    } else if (strncmp(subcommand, ENCRYPT_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        /* ROT-7. Prints ONLY the ciphertext: the plaintext came in from the
         * caller, so echoing it back would put the DEK on stdout for no
         * reason. Contrast genkey, which must print both because KMS is the
         * one that generated the key. */
        struct aws_byte_buf ciphertext_b64 = { 0 };

        rc = encrypt_data(&app_ctx, &ciphertext_b64);
        if (rc == AWS_OP_SUCCESS) {
            fprintf(stdout, "CIPHERTEXT: %s\n", (const char *)ciphertext_b64.buffer);
        } else {
            fprintf(stderr, "Could not encrypt\n");
            exit_rc = 1;
        }
        aws_byte_buf_clean_up(&ciphertext_b64);
        if (rc != AWS_OP_SUCCESS) goto cleanup_hash_table;
    } else if (strncmp(subcommand, GENRANDOM_CMD, MAX_SUB_COMMAND_LENGTH) == 0) {
        struct aws_byte_buf plaintext_b64 = { 0 };

        rc = gen_random(&app_ctx, &plaintext_b64);
        if (rc == AWS_OP_SUCCESS) {
            /* Print the base64-encoded random bytes to stdout */
            fprintf(stdout, "PLAINTEXT: %s\n", (const char *)plaintext_b64.buffer);
        } else {
            fprintf(stderr, "Could not generate random bytes\n");
            exit_rc = 1;
        }
        aws_byte_buf_clean_up(&plaintext_b64);
        if (rc != AWS_OP_SUCCESS) goto cleanup_hash_table;
    } else {
        /* ROT-8: ctx is fully populated by now — wipe before print_commands,
         * which exits and therefore never reaches `cleanup_sdk`. */
        s_app_ctx_secure_clean_up(&app_ctx);
        print_commands(1);
    }

cleanup_hash_table:
    aws_hash_table_clean_up(&app_ctx.encryption_context);
cleanup_sdk:
    /* ROT-8: before the SDK goes away, and on every exit path that reaches the
     * end of main.
     *
     * 🔴 CORRECTED 2026-08-23 (Gemini, signer#55). This comment used to say the
     * `exit(1)` paths in option parsing were "deliberately left alone — at that
     * point nothing has been assigned yet, or the stdin reader has already wiped
     * its own copies." The second clause was the sleight of hand: the stdin
     * reader wipes its own INTERMEDIATE buffers, but by then the values have been
     * copied into `ctx->aws_*`, and every required-argument and subcommand check
     * runs AFTER that block. So a stream that delivered a secret but omitted, say,
     * the session token exited with the secret still live in the heap — while this
     * comment asserted the opposite. A security property documented but absent is
     * worse than one never claimed; that is ROT-8's own lesson, and it applied to
     * ROT-8.
     *
     * Every one of those exits now wipes first. If you add a validation check to
     * `s_parse_options`, call `s_app_ctx_secure_clean_up(ctx)` before its exit —
     * a bare `exit(1)` after the stdin block is a leak. */
    s_app_ctx_secure_clean_up(&app_ctx);
    aws_nitro_enclaves_library_clean_up();

    return exit_rc;
}
