/* ==========================================================================
 * Library Book Lending Tracker — Blockchain Edition
 * ==========================================================================
 * A borrow/return ledger where every event is stored as a block, linked to
 * the previous block by a SHA-256 hash, and digitally signed with an ECDSA
 * (P-256) key so that any after-the-fact edit to a past record is both
 * detectable (hash chain breaks) and unforgeable (signature no longer
 * verifies).
 *
 * Build:   make
 * Run:     ./lending_tracker
 *
 * See README.md for full build/run instructions and openssl_compat.h for
 * why we hand-declare a handful of OpenSSL prototypes instead of including
 * <openssl/...> headers.
 * ==========================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

/* -------------------------------------------------------------------- */
/* Constants                                                            */
/* -------------------------------------------------------------------- */

#define MAX_BOOKS       500
#define MAX_MEMBERS     500
#define HASH_HEX_LEN    64      /* 32 bytes -> 64 hex chars              */
#define SIG_MAX_LEN     72      /* ECDSA-P256 DER signature, worst case  */

#define BOOKS_FILE      "books.txt"
#define MEMBERS_FILE    "members.txt"
#define CHAIN_FILE      "blockchain.dat"
#define KEY_FILE        "library_key.der"

/* -------------------------------------------------------------------- */
/* Data model                                                            */
/* -------------------------------------------------------------------- */

typedef struct {
    char book_id[20];
    char title[80];
    char author[50];
} Book;

typedef struct {
    char member_id[20];
    char full_name[50];
    char course_code[10];
} Member;

typedef struct {
    int            index;
    time_t         timestamp;
    char           book_id[20];
    char           book_title[80];
    char           member_id[20];
    char           member_name[50];
    char           action[10];          /* BORROWED / RETURNED / OVERDUE */
    char           previous_hash[65];
    unsigned char  signature[SIG_MAX_LEN];
    unsigned int   siglen;              /* actual bytes used in signature[] */
    char           hash[65];
} Block;

typedef struct {
    Block *blocks;
    int    count;
    int    capacity;
} Blockchain;

/* -------------------------------------------------------------------- */
/* Globals                                                               */
/* -------------------------------------------------------------------- */

static Book    g_books[MAX_BOOKS];
static int     g_book_count = 0;

static Member  g_members[MAX_MEMBERS];
static int     g_member_count = 0;

static Blockchain g_chain;
static EC_KEY    *g_key = NULL;   /* library's signing key (issues all blocks) */

/* -------------------------------------------------------------------- */
/* Small utilities                                                       */
/* -------------------------------------------------------------------- */

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *out_hex) {
    static const char *digits = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out_hex[i * 2]     = digits[(bytes[i] >> 4) & 0xF];
        out_hex[i * 2 + 1] = digits[bytes[i] & 0xF];
    }
    out_hex[len * 2] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t max_out) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_out) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return (int)(len / 2);
}

/* -------------------------------------------------------------------- */
/* Registry loading                                                      */
/* -------------------------------------------------------------------- */

static int load_books(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("ERROR: Could not open book registry '%s'.\n", path);
        return 0;
    }
    char line[256];
    g_book_count = 0;
    while (fgets(line, sizeof(line), f) && g_book_count < MAX_BOOKS) {
        trim_newline(line);
        if (strlen(line) == 0) continue;
        char *id = strtok(line, ",");
        char *title = strtok(NULL, ",");
        char *author = strtok(NULL, ",");
        if (!id || !title || !author) continue;
        Book *b = &g_books[g_book_count];
        snprintf(b->book_id, sizeof(b->book_id), "%s", id);
        snprintf(b->title,   sizeof(b->title),   "%s", title);
        snprintf(b->author,  sizeof(b->author),  "%s", author);
        g_book_count++;
    }
    fclose(f);
    if (g_book_count == 0) {
        printf("ERROR: Book registry '%s' is empty.\n", path);
        return 0;
    }
    return 1;
}

static int load_members(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        printf("ERROR: Could not open member registry '%s'.\n", path);
        return 0;
    }
    char line[256];
    g_member_count = 0;
    while (fgets(line, sizeof(line), f) && g_member_count < MAX_MEMBERS) {
        trim_newline(line);
        if (strlen(line) == 0) continue;
        char *id = strtok(line, ",");
        char *name = strtok(NULL, ",");
        char *course = strtok(NULL, ",");
        if (!id || !name || !course) continue;
        Member *m = &g_members[g_member_count];
        snprintf(m->member_id,   sizeof(m->member_id),   "%s", id);
        snprintf(m->full_name,   sizeof(m->full_name),   "%s", name);
        snprintf(m->course_code, sizeof(m->course_code), "%s", course);
        g_member_count++;
    }
    fclose(f);
    if (g_member_count == 0) {
        printf("ERROR: Member registry '%s' is empty.\n", path);
        return 0;
    }
    return 1;
}

static Book *find_book(const char *book_id) {
    for (int i = 0; i < g_book_count; i++) {
        if (strcmp(g_books[i].book_id, book_id) == 0) return &g_books[i];
    }
    return NULL;
}

static Member *find_member(const char *member_id) {
    for (int i = 0; i < g_member_count; i++) {
        if (strcmp(g_members[i].member_id, member_id) == 0) return &g_members[i];
    }
    return NULL;
}

/* -------------------------------------------------------------------- */
/* Cryptographic key management                                         */
/* -------------------------------------------------------------------- */

/* Load the library's signing key from disk, or generate + persist a new
 * one on first run. Using one long-lived keypair means every block can be
 * verified against the *same* public key, which is what a "who signed
 * this?" audit needs. */
static EC_KEY *load_or_create_key(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        unsigned char buf[512];
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        const unsigned char *p = buf;
        EC_KEY *key = d2i_ECPrivateKey(NULL, &p, (long)n);
        if (key) {
            printf("[key] Loaded existing library signing key from %s\n", path);
            return key;
        }
        printf("[key] Warning: could not parse %s, generating a new key.\n", path);
    }

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) {
        printf("FATAL: could not allocate EC key.\n");
        exit(1);
    }
    if (!EC_KEY_generate_key(key)) {
        printf("FATAL: EC key generation failed.\n");
        exit(1);
    }

    unsigned char *der = NULL;
    int len = i2d_ECPrivateKey(key, &der);
    if (len > 0) {
        FILE *out = fopen(path, "wb");
        if (out) {
            fwrite(der, 1, (size_t)len, out);
            fclose(out);
            printf("[key] Generated new library signing key -> %s\n", path);
        }
        free(der);
    }
    return key;
}

/* -------------------------------------------------------------------- */
/* Block hashing / signing                                              */
/* -------------------------------------------------------------------- */

/* Serialise the fields that make up a block's *content* (everything except
 * the final chain-linkage hash itself) into a flat buffer. This buffer is
 * what gets (a) SHA-256'd to produce the signing digest and (b) SHA-256'd
 * again, together with the signature, to produce the block hash. */
static int serialize_block_core(const Block *b, char *out, size_t out_size) {
    return snprintf(out, out_size,
        "%d|%ld|%s|%s|%s|%s|%s|%s",
        b->index,
        (long)b->timestamp,
        b->book_id,
        b->book_title,
        b->member_id,
        b->member_name,
        b->action,
        b->previous_hash);
}

static void sign_block(Block *b) {
    char buf[512];
    int len = serialize_block_core(b, buf, sizeof(buf));
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, (size_t)len, digest);

    unsigned int siglen = 0;
    if (!ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH,
                     b->signature, &siglen, g_key)) {
        printf("FATAL: ECDSA_sign failed.\n");
        exit(1);
    }
    b->siglen = siglen;
}

static int verify_block_signature(const Block *b) {
    char buf[512];
    int len = serialize_block_core(b, buf, sizeof(buf));
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, (size_t)len, digest);
    return ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH,
                         b->signature, (int)b->siglen, g_key) == 1;
}

/* The block's stored `hash` field commits to the core fields *and* the
 * signature, so tampering with either the data or a forged/blank
 * signature both change the hash and break the chain linkage. */
static void compute_block_hash(const Block *b, char out_hex[65]) {
    char core[512];
    int len = serialize_block_core(b, core, sizeof(core));

    unsigned char combined[512 + SIG_MAX_LEN];
    memcpy(combined, core, (size_t)len);
    memcpy(combined + len, b->signature, b->siglen);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(combined, (size_t)len + b->siglen, digest);
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, out_hex);
}

/* -------------------------------------------------------------------- */
/* Chain management                                                     */
/* -------------------------------------------------------------------- */

static void chain_init(Blockchain *c) {
    c->capacity = 16;
    c->blocks = malloc(sizeof(Block) * c->capacity);
    c->count = 0;
}

static void chain_append(Blockchain *c, Block *b) {
    if (c->count >= c->capacity) {
        c->capacity *= 2;
        c->blocks = realloc(c->blocks, sizeof(Block) * c->capacity);
    }
    c->blocks[c->count++] = *b;
}

static void create_genesis_block(Blockchain *c) {
    Block g;
    memset(&g, 0, sizeof(g));
    g.index = 0;
    g.timestamp = time(NULL);
    snprintf(g.book_id, sizeof(g.book_id), "-");
    snprintf(g.book_title, sizeof(g.book_title), "GENESIS BLOCK");
    snprintf(g.member_id, sizeof(g.member_id), "-");
    snprintf(g.member_name, sizeof(g.member_name), "-");
    snprintf(g.action, sizeof(g.action), "GENESIS");
    memset(g.previous_hash, '0', 64);
    g.previous_hash[64] = '\0';

    sign_block(&g);
    compute_block_hash(&g, g.hash);
    chain_append(c, &g);
}

/* Find the most recent block referencing this book_id, or NULL. */
static Block *find_last_block_for_book(Blockchain *c, const char *book_id) {
    for (int i = c->count - 1; i >= 0; i--) {
        if (strcmp(c->blocks[i].book_id, book_id) == 0) {
            return &c->blocks[i];
        }
    }
    return NULL;
}

static int book_is_on_loan(Blockchain *c, const char *book_id) {
    Block *last = find_last_block_for_book(c, book_id);
    return last != NULL && strcmp(last->action, "BORROWED") == 0;
}

static void borrow_book(Blockchain *c, const char *book_id, const char *member_id) {
    Book *book = find_book(book_id);
    Member *member = find_member(member_id);
    if (!book || !member) {
        printf("ERROR: Book or Member not found\n");
        return;
    }
    if (book_is_on_loan(c, book_id)) {
        printf("ERROR: Book '%s' (%s) is already on loan.\n", book->title, book_id);
        return;
    }

    Block b;
    memset(&b, 0, sizeof(b));
    b.index = c->count;
    b.timestamp = time(NULL);
    snprintf(b.book_id, sizeof(b.book_id), "%s", book->book_id);
    snprintf(b.book_title, sizeof(b.book_title), "%s", book->title);
    snprintf(b.member_id, sizeof(b.member_id), "%s", member->member_id);
    snprintf(b.member_name, sizeof(b.member_name), "%s", member->full_name);
    snprintf(b.action, sizeof(b.action), "BORROWED");
    snprintf(b.previous_hash, sizeof(b.previous_hash), "%s", c->blocks[c->count - 1].hash);

    sign_block(&b);
    compute_block_hash(&b, b.hash);
    chain_append(c, &b);

    printf("OK: '%s' borrowed by %s. Block #%d recorded.\n", book->title, member->full_name, b.index);
}

static void return_book(Blockchain *c, const char *book_id, const char *member_id) {
    Book *book = find_book(book_id);
    Member *member = find_member(member_id);
    if (!book || !member) {
        printf("ERROR: Book or Member not found\n");
        return;
    }

    Block *last = find_last_block_for_book(c, book_id);
    if (!last || strcmp(last->action, "BORROWED") != 0) {
        printf("ERROR: No active loan found for book '%s'.\n", book_id);
        return;
    }
    if (strcmp(last->member_id, member_id) != 0) {
        printf("ERROR: Book '%s' was borrowed by a different member (%s).\n",
               book_id, last->member_name);
        return;
    }

    Block b;
    memset(&b, 0, sizeof(b));
    b.index = c->count;
    b.timestamp = time(NULL);
    snprintf(b.book_id, sizeof(b.book_id), "%s", book->book_id);
    snprintf(b.book_title, sizeof(b.book_title), "%s", book->title);
    snprintf(b.member_id, sizeof(b.member_id), "%s", member->member_id);
    snprintf(b.member_name, sizeof(b.member_name), "%s", member->full_name);
    snprintf(b.action, sizeof(b.action), "RETURNED");
    snprintf(b.previous_hash, sizeof(b.previous_hash), "%s", c->blocks[c->count - 1].hash);

    sign_block(&b);
    compute_block_hash(&b, b.hash);
    chain_append(c, &b);

    printf("OK: '%s' returned by %s. Block #%d recorded.\n", book->title, member->full_name, b.index);
}

static int validate_chain(Blockchain *c, int verbose) {
    int ok = 1;
    for (int i = 0; i < c->count; i++) {
        Block *b = &c->blocks[i];

        char recomputed[65];
        compute_block_hash(b, recomputed);
        int hash_ok = strcmp(recomputed, b->hash) == 0;

        int link_ok = 1;
        if (i > 0) {
            link_ok = strcmp(b->previous_hash, c->blocks[i - 1].hash) == 0;
        } else {
            char zeros[65];
            memset(zeros, '0', 64);
            zeros[64] = '\0';
            link_ok = strcmp(b->previous_hash, zeros) == 0;
        }

        int sig_ok = verify_block_signature(b);

        if (verbose) {
            printf("Block #%-3d hash:%s  link:%s  signature:%s\n",
                   b->index,
                   hash_ok ? "OK" : "MISMATCH",
                   link_ok ? "OK" : "BROKEN",
                   sig_ok ? "VALID" : "INVALID");
        }

        if (!hash_ok || !link_ok || !sig_ok) ok = 0;
    }
    return ok;
}

static void view_records(Blockchain *c) {
    printf("\n%-4s %-20s %-10s %-25s %-10s %-9s\n",
           "IDX", "TIMESTAMP", "ACTION", "BOOK", "MEMBER", "SIG");
    printf("---------------------------------------------------------------------------------------\n");
    for (int i = 0; i < c->count; i++) {
        Block *b = &c->blocks[i];
        char timebuf[26];
        struct tm *tm_info = localtime(&b->timestamp);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
        int sig_ok = verify_block_signature(b);
        printf("%-4d %-20s %-10s %-25.25s %-10s %-9s\n",
               b->index, timebuf, b->action, b->book_title, b->member_id,
               sig_ok ? "valid" : "INVALID");
    }
    printf("\n");
}

/* -------------------------------------------------------------------- */
/* Persistence: blockchain.dat                                          */
/* -------------------------------------------------------------------- */

static void save_chain(Blockchain *c, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("ERROR: could not write %s\n", path);
        return;
    }
    for (int i = 0; i < c->count; i++) {
        Block *b = &c->blocks[i];
        char sig_hex[SIG_MAX_LEN * 2 + 1];
        bytes_to_hex(b->signature, b->siglen, sig_hex);
        fprintf(f, "%d|%ld|%s|%s|%s|%s|%s|%s|%u|%s|%s\n",
                b->index, (long)b->timestamp, b->book_id, b->book_title,
                b->member_id, b->member_name, b->action, b->previous_hash,
                b->siglen, sig_hex, b->hash);
    }
    fclose(f);
}

static void load_chain(Blockchain *c, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return; /* no saved chain yet — fine, will start fresh */

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        if (strlen(line) == 0) continue;

        Block b;
        memset(&b, 0, sizeof(b));
        char sig_hex[SIG_MAX_LEN * 2 + 1] = {0};
        long ts;

        char *tok = strtok(line, "|");
        int field = 0;
        char *fields[11];
        while (tok && field < 11) { fields[field++] = tok; tok = strtok(NULL, "|"); }
        if (field != 11) continue; /* malformed line, skip */

        b.index = atoi(fields[0]);
        ts = atol(fields[1]);
        b.timestamp = (time_t)ts;
        snprintf(b.book_id, sizeof(b.book_id), "%s", fields[2]);
        snprintf(b.book_title, sizeof(b.book_title), "%s", fields[3]);
        snprintf(b.member_id, sizeof(b.member_id), "%s", fields[4]);
        snprintf(b.member_name, sizeof(b.member_name), "%s", fields[5]);
        snprintf(b.action, sizeof(b.action), "%s", fields[6]);
        snprintf(b.previous_hash, sizeof(b.previous_hash), "%s", fields[7]);
        b.siglen = (unsigned int)atoi(fields[8]);
        snprintf(sig_hex, sizeof(sig_hex), "%s", fields[9]);
        hex_to_bytes(sig_hex, b.signature, SIG_MAX_LEN);
        snprintf(b.hash, sizeof(b.hash), "%s", fields[10]);

        chain_append(c, &b);
    }
    fclose(f);
}

/* -------------------------------------------------------------------- */
/* Tamper-detection demo                                                 */
/* -------------------------------------------------------------------- */

static void tamper_demo(Blockchain *c) {
    if (c->count < 2) {
        printf("Need at least one lending block (beyond genesis) to demo tampering.\n");
        return;
    }
    int idx;
    printf("Enter the index of a block to tamper with (1-%d): ", c->count - 1);
    if (scanf("%d", &idx) != 1) { while (getchar() != '\n'); return; }
    while (getchar() != '\n');
    if (idx < 1 || idx >= c->count) {
        printf("Invalid index.\n");
        return;
    }

    printf("\n--- BEFORE tampering ---\n");
    validate_chain(c, 1);

    printf("\n[Simulating a dishonest edit: changing block #%d's action to RETURNED"
           " without re-signing it, exactly how a manually edited log file would look]\n", idx);
    snprintf(c->blocks[idx].action, sizeof(c->blocks[idx].action), "RETURNED");
    /* Note: we deliberately do NOT recompute the hash or re-sign, because
     * that is precisely what an attacker editing a plain file would do —
     * they don't have the library's private key. */

    printf("\n--- AFTER tampering ---\n");
    int ok = validate_chain(c, 1);
    printf("\nChain validation result: %s\n", ok ? "VALID" : "TAMPERING DETECTED");

    /* Restore in-memory copy so the demo doesn't corrupt the working chain
     * for the rest of the session (the on-disk file was never touched). */
    load_chain(c, CHAIN_FILE);
}

/* -------------------------------------------------------------------- */
/* CLI                                                                   */
/* -------------------------------------------------------------------- */

static void read_line(char *buf, size_t size) {
    if (fgets(buf, (int)size, stdin)) trim_newline(buf);
}

static void print_menu(void) {
    printf("\n===== Library Blockchain Lending Tracker =====\n");
    printf("1. Borrow a book\n");
    printf("2. Return a book\n");
    printf("3. View all lending records\n");
    printf("4. Validate chain integrity\n");
    printf("5. Demonstrate tamper detection\n");
    printf("6. List books/members registries\n");
    printf("0. Exit\n");
    printf("Choose an option: ");
}

int main(void) {
    printf("Loading registries...\n");
    if (!load_books(BOOKS_FILE) || !load_members(MEMBERS_FILE)) {
        printf("Startup aborted: fix the registry files and re-run.\n");
        return 1;
    }
    printf("Loaded %d book(s) and %d member(s).\n", g_book_count, g_member_count);

    g_key = load_or_create_key(KEY_FILE);

    chain_init(&g_chain);
    load_chain(&g_chain, CHAIN_FILE);
    if (g_chain.count == 0) {
        create_genesis_block(&g_chain);
        printf("Genesis block created.\n");
    } else {
        printf("Loaded existing chain with %d block(s) from %s.\n", g_chain.count, CHAIN_FILE);
    }

    int running = 1;
    while (running) {
        print_menu();
        int choice;
        if (scanf("%d", &choice) != 1) { while (getchar() != '\n'); continue; }
        while (getchar() != '\n');

        char book_id[20], member_id[20];

        switch (choice) {
            case 1:
                printf("Book ID: ");   read_line(book_id, sizeof(book_id));
                printf("Member ID: "); read_line(member_id, sizeof(member_id));
                borrow_book(&g_chain, book_id, member_id);
                save_chain(&g_chain, CHAIN_FILE);
                break;
            case 2:
                printf("Book ID: ");   read_line(book_id, sizeof(book_id));
                printf("Member ID: "); read_line(member_id, sizeof(member_id));
                return_book(&g_chain, book_id, member_id);
                save_chain(&g_chain, CHAIN_FILE);
                break;
            case 3:
                view_records(&g_chain);
                break;
            case 4: {
                int ok = validate_chain(&g_chain, 1);
                printf("\nOverall chain status: %s\n", ok ? "VALID" : "TAMPERED / CORRUPT");
                break;
            }
            case 5:
                tamper_demo(&g_chain);
                break;
            case 6:
                printf("\nBooks:\n");
                for (int i = 0; i < g_book_count; i++)
                    printf("  %-8s %-30s %s\n", g_books[i].book_id, g_books[i].title, g_books[i].author);
                printf("\nMembers:\n");
                for (int i = 0; i < g_member_count; i++)
                    printf("  %-8s %-25s %s\n", g_members[i].member_id, g_members[i].full_name, g_members[i].course_code);
                break;
            case 0:
                running = 0;
                break;
            default:
                printf("Unknown option.\n");
        }
    }

    free(g_chain.blocks);
    EC_KEY_free(g_key);
    printf("Goodbye.\n");
    return 0;
}
