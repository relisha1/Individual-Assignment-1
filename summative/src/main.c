/* ==========================================================================
 * Library Blockchain Lending Tracker — Summative
 * ==========================================================================
 * Combines and extends Formative 1 (immutable ledger, registries, hashing,
 * signatures, chain validation) and Formative 2 (token rewards, pending
 * pool, mining, UTXO and account ledgers) with: copy-level inventory,
 * reservations, renewals, fines, Merkle-tree batched blocks, a real
 * per-member ECDSA keypair for every signer, nonce-based replay
 * protection, misuse/fraud detection, full disk persistence, and a
 * named-command CLI (type commands like a real tool: "borrow_book BK001
 * C001 ALU001 0", not a numbered menu).
 *
 * Build:   make
 * Run:     ./lending_tracker
 * Type "help" once it's running for the full command list.
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
/* Constants                                                             */
/* -------------------------------------------------------------------- */

#define MAX_BOOKS     500
#define MAX_MEMBERS   500
#define MAX_COPIES    1000
#define MAX_UTXO      2000
#define SIG_MAX_LEN   72

#define BOOKS_FILE    "books.txt"
#define MEMBERS_FILE  "members.txt"
#define COPIES_FILE   "copies.txt"

#define KEYS_FILE        "member_keys.dat"
#define CHAIN_FILE       "chain.dat"
#define COPY_STATE_FILE  "copy_state.dat"
#define RESERVE_FILE     "reservations.dat"
#define POOL_FILE        "pool.dat"
#define UTXO_FILE        "utxo.dat"
#define ACCOUNTS_FILE    "accounts.dat"
#define NONCES_FILE      "member_nonces.dat"
#define FINES_FILE       "fines.dat"
#define META_FILE        "meta.dat"

/* Demo-scale time constants. Documented in the report: a real deployment
 * would use real days, but that makes a short recording impossible, so
 * these are compressed to seconds. The real-world value is given in a
 * comment next to each one. */
#define LOAN_PERIOD_SECONDS       20   /* real value: 14 * 24 * 3600 (14 days)   */
#define RENEWAL_PERIOD_SECONDS    20   /* real value: 7  * 24 * 3600 (7 days)    */
#define OVERDUE_UNIT_SECONDS      20   /* real value: 24 * 3600 (1 day)          */
#define RAPID_REBORROW_WINDOW_SEC 20   /* real value: 24 * 3600 (24 hours)       */
#define MAX_RENEWALS              2

#define FINE_PER_UNIT         2
#define ON_TIME_REWARD        10
#define LATE_REWARD           5
#define TRANSFER_FEE          1
#define MAX_CONCURRENT_BORROWS 3

#define RECORDS_PER_BLOCK     3
#define SOLO_BLOCK_REWARD     50
#define POOL_FEE_PERCENT      2
#define CLOUD_RENTAL_FEE      6

/* -------------------------------------------------------------------- */
/* Registries                                                            */
/* -------------------------------------------------------------------- */

typedef struct { char book_id[20]; char title[80]; char author[50]; } Book;
typedef struct { char member_id[20]; char full_name[50]; char course_code[10]; } Member;

typedef enum { COND_NEW = 0, COND_GOOD = 1, COND_WORN = 2, COND_LOST = 3 } Condition;
typedef enum { ST_AVAILABLE = 0, ST_BORROWED = 1, ST_RESERVED = 2, ST_LOST = 3 } CopyState;

static const char *COND_NAME[] = { "NEW", "GOOD", "WORN", "LOST" };
static const char *STATE_NAME[] = { "AVAILABLE", "BORROWED", "RESERVED", "LOST" };

typedef struct {
    char copy_id[20];
    char book_id[20];
    Condition condition;
    CopyState state;
    char holder_id[20];   /* empty string if nobody holds it */
    time_t due_date;
    int renewals_used;
    int scan_fine_charged; /* running total already added to the holder's
                             * outstanding fine by check_overdue while this
                             * copy is still out, so the eventual return
                             * confirmation can net off the correct amount
                             * instead of charging the same lateness twice */
} Copy;

typedef struct ResNode {
    char member_id[20];
    time_t reservation_date;
    struct ResNode *next;
} ResNode;

/* -------------------------------------------------------------------- */
/* Lending records and blocks                                            */
/* -------------------------------------------------------------------- */

typedef struct {
    char record_id[65];
    char book_id[20];
    char copy_id[20];
    char book_title[80];
    char member_id[20];
    char member_name[50];
    char action[10];        /* BORROWED/RETURNED/RESERVED/RENEWED/OVERDUE */
    time_t timestamp;
    time_t due_date;
    int fine_amount;
    int token_reward;
    char tx_id[65];
    unsigned long nonce;
    unsigned char signature[SIG_MAX_LEN];
    unsigned int siglen;
} LendingRecord;

typedef struct {
    LendingRecord rec;
    char status[12];        /* PENDING or SUSPICIOUS */
    int overdue_priority;   /* 0 = overdue-related (goes first), 1 = normal */
    time_t priority_date;
    int reported_condition; /* Condition enum value; only meaningful for a
                              * RETURNED item with a reported condition, -1
                              * otherwise. Applied to the copy only once
                              * this item is actually mined, same as every
                              * other effect of a return. */
} PendingItem;

typedef struct {
    int index;
    time_t timestamp;
    int record_count;
    LendingRecord records[RECORDS_PER_BLOCK];
    char previous_hash[65];
    char merkle_root[65];
    char sealed_by[20];
    int token_reward;
    char transaction_id[65];
    unsigned long nonce;
    char hash[65];
} Block;

typedef struct { Block *items; int count; int capacity; } BlockArray;
typedef struct { PendingItem *items; int count; int capacity; } PendingPool;

/* -------------------------------------------------------------------- */
/* Token ledgers (same two models as Formative 2)                        */
/* -------------------------------------------------------------------- */

typedef struct { char tx_id[65]; int output_index; char owner[20]; int amount; int spent; } UTXO;

typedef struct TxRecord {
    char sender[20]; char recipient[20]; int amount; int fee; unsigned long nonce;
    struct TxRecord *next;
} TxRecord;

typedef struct { char member_id[20]; int balance; TxRecord *history; } Account;

typedef enum { MODEL_UTXO = 0, MODEL_ACCOUNT = 1 } LedgerModel;

/* -------------------------------------------------------------------- */
/* Globals                                                                */
/* -------------------------------------------------------------------- */

static Book   g_books[MAX_BOOKS];   static int g_book_count = 0;
static Member g_members[MAX_MEMBERS]; static int g_member_count = 0;
static Copy   g_copies[MAX_COPIES]; static int g_copy_count = 0;

static EC_KEY *g_member_keys[MAX_MEMBERS];
static char    g_member_pubkey_hex[MAX_MEMBERS][140];
static unsigned long g_member_nonce[MAX_MEMBERS];   /* unified replay-protection nonce */
static int     g_member_fine[MAX_MEMBERS];

static ResNode *g_res_head[MAX_BOOKS];
static ResNode *g_res_tail[MAX_BOOKS];

static BlockArray  g_chain;
static PendingPool g_pool;

static UTXO    g_utxos[MAX_UTXO]; static int g_utxo_count = 0;
static Account g_accounts[MAX_MEMBERS];

static LedgerModel g_model = MODEL_UTXO;
static int g_difficulty = 2;
static int g_chain_was_valid_on_load = 1;

/* -------------------------------------------------------------------- */
/* Small utilities                                                       */
/* -------------------------------------------------------------------- */

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}
static void bytes_to_hex(const unsigned char *b, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) { out[i*2] = d[(b[i]>>4)&0xF]; out[i*2+1] = d[b[i]&0xF]; }
    out[len*2] = '\0';
}
static int hex_to_bytes(const char *hex, unsigned char *out, size_t max_out) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_out) return -1;
    for (size_t i = 0; i < len/2; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%2x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return (int)(len/2);
}
static void sha256_hex(const unsigned char *data, size_t len, char out[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, out);
}
static int leading_zero_hex(const char *hex, int n) {
    for (int i = 0; i < n; i++) if (hex[i] != '0') return 0;
    return 1;
}
static void zeros64(char out[65]) { memset(out, '0', 64); out[64] = '\0'; }

/* -------------------------------------------------------------------- */
/* Registry + inventory loading                                          */
/* -------------------------------------------------------------------- */

static int load_books(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERROR: Could not open book registry '%s'.\n", path); return 0; }
    char line[256];
    while (fgets(line, sizeof(line), f) && g_book_count < MAX_BOOKS) {
        trim_newline(line); if (!line[0]) continue;
        char *id = strtok(line, ","), *title = strtok(NULL, ","), *author = strtok(NULL, ",");
        if (!id || !title || !author) continue;
        Book *b = &g_books[g_book_count++];
        snprintf(b->book_id, sizeof(b->book_id), "%s", id);
        snprintf(b->title, sizeof(b->title), "%s", title);
        snprintf(b->author, sizeof(b->author), "%s", author);
    }
    fclose(f);
    if (g_book_count == 0) { printf("ERROR: Book registry '%s' is empty.\n", path); return 0; }
    return 1;
}

static int load_members(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERROR: Could not open member registry '%s'.\n", path); return 0; }
    char line[256];
    while (fgets(line, sizeof(line), f) && g_member_count < MAX_MEMBERS) {
        trim_newline(line); if (!line[0]) continue;
        char *id = strtok(line, ","), *name = strtok(NULL, ","), *course = strtok(NULL, ",");
        if (!id || !name || !course) continue;
        Member *m = &g_members[g_member_count++];
        snprintf(m->member_id, sizeof(m->member_id), "%s", id);
        snprintf(m->full_name, sizeof(m->full_name), "%s", name);
        snprintf(m->course_code, sizeof(m->course_code), "%s", course);
    }
    fclose(f);
    if (g_member_count == 0) { printf("ERROR: Member registry '%s' is empty.\n", path); return 0; }
    return 1;
}

static int load_copies(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERROR: Could not open copy registry '%s'.\n", path); return 0; }
    char line[256];
    while (fgets(line, sizeof(line), f) && g_copy_count < MAX_COPIES) {
        trim_newline(line); if (!line[0]) continue;
        char *id = strtok(line, ","), *book = strtok(NULL, ","), *cond = strtok(NULL, ",");
        if (!id || !book) continue;
        Copy *c = &g_copies[g_copy_count++];
        snprintf(c->copy_id, sizeof(c->copy_id), "%s", id);
        snprintf(c->book_id, sizeof(c->book_id), "%s", book);
        c->condition = COND_NEW;
        if (cond) {
            if (strcmp(cond, "GOOD") == 0) c->condition = COND_GOOD;
            else if (strcmp(cond, "WORN") == 0) c->condition = COND_WORN;
            else if (strcmp(cond, "LOST") == 0) c->condition = COND_LOST;
        }
        c->state = (c->condition == COND_LOST) ? ST_LOST : ST_AVAILABLE;
        c->holder_id[0] = '\0';
        c->due_date = 0;
        c->renewals_used = 0;
        c->scan_fine_charged = 0;
    }
    fclose(f);
    if (g_copy_count == 0) { printf("ERROR: Copy registry '%s' is empty.\n", path); return 0; }
    return 1;
}

static Book  *find_book(const char *id)  { for (int i=0;i<g_book_count;i++)  if (!strcmp(g_books[i].book_id,id))  return &g_books[i];  return NULL; }
static int    find_member_idx(const char *id) { for (int i=0;i<g_member_count;i++) if (!strcmp(g_members[i].member_id,id)) return i; return -1; }
static Copy  *find_copy(const char *id)  { for (int i=0;i<g_copy_count;i++)  if (!strcmp(g_copies[i].copy_id,id))  return &g_copies[i];  return NULL; }
static int    find_book_idx(const char *id) { for (int i=0;i<g_book_count;i++) if (!strcmp(g_books[i].book_id,id)) return i; return -1; }

/* -------------------------------------------------------------------- */
/* Per-member ECDSA keys                                                 */
/* -------------------------------------------------------------------- */

static void set_pubkey_hex(int idx) {
    unsigned char *pub = NULL;
    int len = i2o_ECPublicKey(g_member_keys[idx], &pub);
    if (len > 0) { bytes_to_hex(pub, (size_t)len, g_member_pubkey_hex[idx]); free(pub); }
}

static EC_KEY *generate_member_key(void) {
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!k || !EC_KEY_generate_key(k)) { printf("FATAL: key generation failed.\n"); exit(1); }
    return k;
}

static void save_member_keys(void) {
    FILE *f = fopen(KEYS_FILE, "w");
    if (!f) { printf("WARNING: could not write %s\n", KEYS_FILE); return; }
    for (int i = 0; i < g_member_count; i++) {
        unsigned char *der = NULL;
        int len = i2d_ECPrivateKey(g_member_keys[i], &der);
        if (len > 0) {
            char hex[1024];
            bytes_to_hex(der, (size_t)len, hex);
            fprintf(f, "%s|%s\n", g_members[i].member_id, hex);
            free(der);
        }
    }
    fclose(f);
}

static void load_or_create_member_keys(void) {
    char loaded[MAX_MEMBERS] = {0};
    FILE *f = fopen(KEYS_FILE, "r");
    if (f) {
        char line[1200];
        while (fgets(line, sizeof(line), f)) {
            trim_newline(line); if (!line[0]) continue;
            char *id = strtok(line, "|"), *hex = strtok(NULL, "|");
            if (!id || !hex) continue;
            int idx = find_member_idx(id);
            if (idx < 0) continue;
            unsigned char der[1024];
            int n = hex_to_bytes(hex, der, sizeof(der));
            if (n > 0) {
                const unsigned char *p = der;
                EC_KEY *k = d2i_ECPrivateKey(NULL, &p, n);
                if (k) { g_member_keys[idx] = k; loaded[idx] = 1; }
            }
        }
        fclose(f);
    }
    int any_new = 0;
    for (int i = 0; i < g_member_count; i++) {
        if (!loaded[i]) { g_member_keys[i] = generate_member_key(); any_new = 1; }
        set_pubkey_hex(i);
    }
    if (any_new) { save_member_keys(); printf("[keys] Generated signing keys for any new members -> %s\n", KEYS_FILE); }
    else printf("[keys] Loaded existing member signing keys from %s\n", KEYS_FILE);
}

/* -------------------------------------------------------------------- */
/* Record serialization, signing, Merkle tree, block hashing             */
/* -------------------------------------------------------------------- */

static int serialize_record_core(const LendingRecord *r, char *out, size_t out_size) {
    return snprintf(out, out_size, "%s|%s|%s|%s|%s|%s|%ld|%ld|%d|%d|%s|%lu",
        r->book_id, r->copy_id, r->book_title, r->member_id, r->member_name, r->action,
        (long)r->timestamp, (long)r->due_date, r->fine_amount, r->token_reward, r->tx_id, r->nonce);
}

static void record_leaf_hash(const LendingRecord *r, char out[65]) {
    char buf[600];
    int len = serialize_record_core(r, buf, sizeof(buf));
    sha256_hex((unsigned char *)buf, (size_t)len, out);
}

static void sign_record(LendingRecord *r, EC_KEY *signer) {
    char buf[600];
    int len = serialize_record_core(r, buf, sizeof(buf));
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, (size_t)len, digest);
    unsigned int siglen = 0;
    if (!ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH, r->signature, &siglen, signer)) {
        printf("FATAL: ECDSA_sign failed.\n"); exit(1);
    }
    r->siglen = siglen;
}

static int verify_record_signature(const LendingRecord *r) {
    int idx = find_member_idx(r->member_id);
    if (idx < 0 || !g_member_keys[idx]) return 0;
    char buf[600];
    int len = serialize_record_core(r, buf, sizeof(buf));
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, (size_t)len, digest);
    return ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, r->signature, (int)r->siglen, g_member_keys[idx]) == 1;
}

/* Merkle tree built from scratch: pair up leaf hashes, duplicate the last
 * one if the level has an odd count (the standard Bitcoin-style rule),
 * and keep hashing pairs together until only one hash (the root) remains. */
static void compute_merkle_root(const LendingRecord *records, int n, char out[65]) {
    if (n == 0) { sha256_hex((unsigned char *)"", 0, out); return; }
    char level[RECORDS_PER_BLOCK][65];
    for (int i = 0; i < n; i++) record_leaf_hash(&records[i], level[i]);
    int count = n;
    while (count > 1) {
        int next_count = 0;
        char next[RECORDS_PER_BLOCK][65];
        for (int i = 0; i < count; i += 2) {
            char combined[130];
            if (i + 1 < count) snprintf(combined, sizeof(combined), "%s%s", level[i], level[i+1]);
            else               snprintf(combined, sizeof(combined), "%s%s", level[i], level[i]);
            sha256_hex((unsigned char *)combined, strlen(combined), next[next_count++]);
        }
        for (int i = 0; i < next_count; i++) memcpy(level[i], next[i], 65);
        count = next_count;
    }
    memcpy(out, level[0], 65);
}

static int serialize_block_core(const Block *b, char *out, size_t out_size) {
    return snprintf(out, out_size, "%d|%ld|%d|%s|%s|%s|%d|%s",
        b->index, (long)b->timestamp, b->record_count, b->previous_hash, b->merkle_root,
        b->sealed_by, b->token_reward, b->transaction_id);
}

static void compute_block_pow_hash(const Block *b, char out[65]) {
    char core[400];
    int len = serialize_block_core(b, core, sizeof(core));
    char full[460];
    int flen = snprintf(full, sizeof(full), "%.*s|%lu", len, core, b->nonce);
    sha256_hex((unsigned char *)full, (size_t)flen, out);
}

/* -------------------------------------------------------------------- */
/* Growable arrays                                                       */
/* -------------------------------------------------------------------- */

static void chain_init(void) { g_chain.capacity = 16; g_chain.items = malloc(sizeof(Block)*g_chain.capacity); g_chain.count = 0; }
static void chain_append(Block *b) {
    if (g_chain.count >= g_chain.capacity) { g_chain.capacity *= 2; g_chain.items = realloc(g_chain.items, sizeof(Block)*g_chain.capacity); }
    g_chain.items[g_chain.count++] = *b;
}
static void pool_init(void) { g_pool.capacity = 16; g_pool.items = malloc(sizeof(PendingItem)*g_pool.capacity); g_pool.count = 0; }
static void pool_append(PendingItem *p) {
    if (g_pool.count >= g_pool.capacity) { g_pool.capacity *= 2; g_pool.items = realloc(g_pool.items, sizeof(PendingItem)*g_pool.capacity); }
    g_pool.items[g_pool.count++] = *p;
}
static void pool_remove_at(int idx) {
    memmove(&g_pool.items[idx], &g_pool.items[idx+1], sizeof(PendingItem)*(g_pool.count-idx-1));
    g_pool.count--;
}

/* -------------------------------------------------------------------- */
/* Reservation queue                                                      */
/* -------------------------------------------------------------------- */

static void enqueue_reservation(int book_idx, const char *member_id) {
    ResNode *n = malloc(sizeof(ResNode));
    snprintf(n->member_id, sizeof(n->member_id), "%s", member_id);
    n->reservation_date = time(NULL);
    n->next = NULL;
    if (!g_res_head[book_idx]) g_res_head[book_idx] = n;
    else g_res_tail[book_idx]->next = n;
    g_res_tail[book_idx] = n;
}
static int pop_reservation(int book_idx, char out_member[20]) {
    if (!g_res_head[book_idx]) return 0;
    ResNode *n = g_res_head[book_idx];
    snprintf(out_member, 20, "%s", n->member_id);
    g_res_head[book_idx] = n->next;
    if (!g_res_head[book_idx]) g_res_tail[book_idx] = NULL;
    free(n);
    return 1;
}

/* -------------------------------------------------------------------- */
/* Fines                                                                  */
/* -------------------------------------------------------------------- */

static int compute_fine(time_t due_date, time_t now) {
    if (now <= due_date) return 0;
    long overdue_seconds = (long)(now - due_date);
    int units = (int)(overdue_seconds / OVERDUE_UNIT_SECONDS) + 1;
    return units * FINE_PER_UNIT;
}

/* -------------------------------------------------------------------- */
/* Token ledgers: UTXO                                                   */
/* -------------------------------------------------------------------- */

static int utxo_balance(const char *member_id) {
    int total = 0;
    for (int i = 0; i < g_utxo_count; i++)
        if (!g_utxos[i].spent && !strcmp(g_utxos[i].owner, member_id)) total += g_utxos[i].amount;
    return total;
}
static void utxo_add(const char *tx_id, int out_idx, const char *owner, int amount) {
    if (g_utxo_count >= MAX_UTXO) { printf("WARNING: UTXO set full.\n"); return; }
    UTXO *u = &g_utxos[g_utxo_count++];
    snprintf(u->tx_id, sizeof(u->tx_id), "%s", tx_id);
    u->output_index = out_idx; snprintf(u->owner, sizeof(u->owner), "%s", owner);
    u->amount = amount; u->spent = 0;
}
static void credit_utxo_reward(const char *member_id, int amount, const char *tx_id) { utxo_add(tx_id, 0, member_id, amount); }

static int utxo_transfer(const char *sender, const char *recipient, int amount) {
    int need = amount + TRANSFER_FEE, collected = 0, idx[MAX_UTXO], idx_count = 0;
    for (int i = 0; i < g_utxo_count && collected < need; i++)
        if (!g_utxos[i].spent && !strcmp(g_utxos[i].owner, sender)) { idx[idx_count++] = i; collected += g_utxos[i].amount; }
    if (collected < need) { printf("ERROR: insufficient funds. %s has %d, needs %d.\n", sender, utxo_balance(sender), need); return 0; }
    for (int i = 0; i < idx_count; i++) g_utxos[idx[i]].spent = 1;
    char tx_id[65], raw[128];
    snprintf(raw, sizeof(raw), "%s|%s|%d|%ld", sender, recipient, amount, (long)time(NULL));
    sha256_hex((unsigned char *)raw, strlen(raw), tx_id);
    utxo_add(tx_id, 0, recipient, amount);
    int change = collected - need;
    if (change > 0) utxo_add(tx_id, 1, sender, change);
    printf("OK: %s sent %d to %s (fee %d).%s\n", sender, amount, recipient, TRANSFER_FEE,
           change > 0 ? " Change returned." : "");
    return 1;
}
static void print_utxo_set(void) {
    printf("\n%-10s %-4s %-8s %-6s %s\n", "OWNER", "OUT#", "AMOUNT", "SPENT", "TX ID");
    printf("---------------------------------------------------\n");
    for (int i = 0; i < g_utxo_count; i++) {
        UTXO *u = &g_utxos[i];
        printf("%-10s %-4d %-8d %-6s %.12s\n", u->owner, u->output_index, u->amount, u->spent ? "yes" : "no", u->tx_id);
    }
    printf("\nBalances:\n");
    for (int i = 0; i < g_member_count; i++) printf("  %-10s %d\n", g_members[i].member_id, utxo_balance(g_members[i].member_id));
}

/* -------------------------------------------------------------------- */
/* Token ledgers: Account balances                                       */
/* -------------------------------------------------------------------- */

static Account *find_account(const char *member_id) {
    for (int i = 0; i < g_member_count; i++) if (!strcmp(g_accounts[i].member_id, member_id)) return &g_accounts[i];
    return NULL;
}
static void init_accounts(void) {
    for (int i = 0; i < g_member_count; i++) {
        snprintf(g_accounts[i].member_id, sizeof(g_accounts[i].member_id), "%s", g_members[i].member_id);
        g_accounts[i].balance = 0; g_accounts[i].history = NULL;
    }
}
static void append_history(Account *a, const char *s, const char *r, int amt, int fee, unsigned long nonce) {
    TxRecord *t = malloc(sizeof(TxRecord));
    snprintf(t->sender, sizeof(t->sender), "%s", s); snprintf(t->recipient, sizeof(t->recipient), "%s", r);
    t->amount = amt; t->fee = fee; t->nonce = nonce; t->next = NULL;
    if (!a->history) { a->history = t; return; }
    TxRecord *c = a->history; while (c->next) c = c->next; c->next = t;
}
static void credit_account_reward(const char *member_id, int amount) {
    Account *a = find_account(member_id); if (!a) return;
    a->balance += amount; append_history(a, "SYSTEM", member_id, amount, 0, 0);
}
/* explicit_nonce < 0 means "use whatever the sender's current expected
 * nonce is" (the normal path, used by every real CLI transfer). Passing
 * an explicit value lets simulate_replay below deliberately submit a
 * stale one so the rejection path can actually be exercised and shown. */
static int account_transfer_ex(const char *sender, const char *recipient, int amount, long explicit_nonce) {
    int sidx = find_member_idx(sender), ridx = find_member_idx(recipient);
    if (sidx < 0 || ridx < 0) { printf("ERROR: Book or Member not found\n"); return 0; }

    unsigned long submitted = (explicit_nonce >= 0) ? (unsigned long)explicit_nonce : g_member_nonce[sidx];
    if (submitted != g_member_nonce[sidx]) {
        printf("ERROR: wrong or reused nonce. Expected %lu, got %lu. Transfer rejected.\n",
               g_member_nonce[sidx], submitted);
        return 0;
    }

    int need = amount + TRANSFER_FEE;
    if (g_accounts[sidx].balance < need) {
        printf("ERROR: insufficient balance. %s has %d, needs %d.\n", sender, g_accounts[sidx].balance, need);
        return 0;
    }
    g_accounts[sidx].balance -= need;
    g_accounts[ridx].balance += amount;
    append_history(&g_accounts[sidx], sender, recipient, amount, TRANSFER_FEE, submitted);
    append_history(&g_accounts[ridx], sender, recipient, amount, TRANSFER_FEE, submitted);
    g_member_nonce[sidx]++;
    printf("OK: %s sent %d to %s (fee %d, nonce %lu). New balance: %d.\n",
           sender, amount, recipient, TRANSFER_FEE, submitted, g_accounts[sidx].balance);
    return 1;
}
static int account_transfer(const char *sender, const char *recipient, int amount) {
    return account_transfer_ex(sender, recipient, amount, -1);
}

/* Demonstrates nonce-based replay protection: deliberately resubmits the
 * sender's most recently *used* nonce (now stale) instead of their current
 * expected one, and shows it being rejected. This is a test/demo utility
 * added beyond the required command list, not a real user-facing transfer
 * path — the real transfer commands never let a stale nonce through,
 * since they always auto-fill the correct next one. */
static void cmd_simulate_replay(const char *member_id) {
    int idx = find_member_idx(member_id);
    if (idx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    if (g_member_nonce[idx] == 0) { printf("%s has no confirmed transaction yet, nothing to replay.\n", member_id); return; }
    unsigned long stale = g_member_nonce[idx] - 1;
    printf("Replaying %s's old transaction with already-used nonce %lu (current expected: %lu)...\n",
           member_id, stale, g_member_nonce[idx]);
    account_transfer_ex(member_id, member_id, 1, (long)stale);
}
static void print_accounts(void) {
    printf("\n%-10s %-10s\n", "MEMBER", "BALANCE");
    printf("----------------------\n");
    for (int i = 0; i < g_member_count; i++) printf("%-10s %-10d\n", g_accounts[i].member_id, g_accounts[i].balance);
}
static void print_tx_history(const char *member_id) {
    Account *a = find_account(member_id);
    if (!a) { printf("ERROR: Book or Member not found\n"); return; }
    printf("\nTransaction history for %s:\n", member_id);
    if (!a->history) { printf("  (none yet)\n"); return; }
    for (TxRecord *t = a->history; t; t = t->next)
        printf("  %s -> %s | amount %d | fee %d | nonce %lu\n", t->sender, t->recipient, t->amount, t->fee, t->nonce);
}

/* -------------------------------------------------------------------- */
/* Fraud / misuse heuristics                                             */
/* -------------------------------------------------------------------- */

static int count_active_borrows(const char *member_id) {
    int n = 0;
    for (int i = 0; i < g_copy_count; i++)
        if (g_copies[i].state == ST_BORROWED && !strcmp(g_copies[i].holder_id, member_id)) n++;
    for (int i = 0; i < g_pool.count; i++)
        if (!strcmp(g_pool.items[i].status, "PENDING") && !strcmp(g_pool.items[i].rec.action, "BORROWED")
            && !strcmp(g_pool.items[i].rec.member_id, member_id)) n++;
    return n;
}

static int recent_return_time(const char *book_id, const char *member_id, time_t *out_time) {
    for (int i = g_chain.count - 1; i >= 0; i--) {
        Block *blk = &g_chain.items[i];
        for (int j = 0; j < blk->record_count; j++) {
            LendingRecord *r = &blk->records[j];
            if (!strcmp(r->action, "RETURNED") && !strcmp(r->book_id, book_id) && !strcmp(r->member_id, member_id)) {
                *out_time = r->timestamp; return 1;
            }
        }
    }
    return 0;
}

static int request_id_exists(const char *request_id) {
    for (int i = 0; i < g_pool.count; i++) if (!strcmp(g_pool.items[i].rec.record_id, request_id)) return 1;
    for (int i = 0; i < g_chain.count; i++) {
        Block *blk = &g_chain.items[i];
        for (int j = 0; j < blk->record_count; j++) if (!strcmp(blk->records[j].record_id, request_id)) return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------- */
/* Nonce-based replay protection                                         */
/* -------------------------------------------------------------------- */

static unsigned long expected_nonce(int member_idx) { return g_member_nonce[member_idx]; }

/* -------------------------------------------------------------------- */
/* Pending pool operations                                               */
/* -------------------------------------------------------------------- */

static void make_request_id(const char *member_id, const char *book_id, const char *action, time_t ts, unsigned long nonce, char out[65]) {
    char raw[160];
    snprintf(raw, sizeof(raw), "%s|%s|%s|%ld|%lu", member_id, book_id, action, (long)ts, nonce);
    sha256_hex((unsigned char *)raw, strlen(raw), out);
}

/* Builds, signs, fraud-checks and queues a lending request. Returns 1 if
 * queued (PENDING or SUSPICIOUS), 0 if rejected outright (bad IDs or bad
 * nonce — those never even make it into the pool). */
static int submit_request(const char *book_id, const char *copy_id, const char *member_id,
                           const char *action, time_t due_date, int fine_amount,
                           int token_reward, const char *tx_id,
                           int overdue_priority, time_t priority_date, int *out_idx) {
    Book *book = find_book(book_id);
    int midx = find_member_idx(member_id);
    if (!book || midx < 0) { printf("ERROR: Book or Member not found\n"); return 0; }

    time_t now = time(NULL);
    unsigned long nonce = expected_nonce(midx);

    PendingItem item; memset(&item, 0, sizeof(item));
    item.reported_condition = -1; /* -1 = no condition change reported */
    LendingRecord *r = &item.rec;
    snprintf(r->book_id, sizeof(r->book_id), "%s", book_id);
    if (copy_id) snprintf(r->copy_id, sizeof(r->copy_id), "%s", copy_id);
    snprintf(r->book_title, sizeof(r->book_title), "%s", book->title);
    snprintf(r->member_id, sizeof(r->member_id), "%s", member_id);
    snprintf(r->member_name, sizeof(r->member_name), "%s", g_members[midx].full_name);
    snprintf(r->action, sizeof(r->action), "%s", action);
    r->timestamp = now; r->due_date = due_date; r->fine_amount = fine_amount;
    r->token_reward = token_reward; snprintf(r->tx_id, sizeof(r->tx_id), "%s", tx_id ? tx_id : "-");
    r->nonce = nonce;
    make_request_id(member_id, book_id, action, now, nonce, r->record_id);

    if (request_id_exists(r->record_id)) {
        printf("FLAGGED SUSPICIOUS: duplicate request detected.\n");
        snprintf(item.status, sizeof(item.status), "SUSPICIOUS");
    } else {
        snprintf(item.status, sizeof(item.status), "PENDING");
    }

    sign_record(r, g_member_keys[midx]);
    if (!verify_record_signature(r)) { printf("ERROR: signature verification failed unexpectedly.\n"); return 0; }

    item.overdue_priority = overdue_priority;
    item.priority_date = priority_date;
    pool_append(&item);
    if (out_idx) *out_idx = g_pool.count - 1;
    return 1;
}

/* -------------------------------------------------------------------- */
/* Lending operations                                                    */
/* -------------------------------------------------------------------- */

/* True if some not-yet-mined request in the pool already claims this copy
 * (a pending BORROWED or RENEWED on it) — used so two concurrent borrow
 * requests can't both be handed the same physical copy before mining. */
static int copy_has_pending_claim(const char *copy_id) {
    for (int i = 0; i < g_pool.count; i++) {
        PendingItem *it = &g_pool.items[i];
        if (!strcmp(it->rec.copy_id, copy_id) &&
            (!strcmp(it->rec.action, "BORROWED") || !strcmp(it->rec.action, "RENEWED")))
            return 1;
    }
    return 0;
}

static void cmd_borrow_book(const char *book_id, const char *member_id) {
    Book *book = find_book(book_id);
    int midx = find_member_idx(member_id);
    if (!book || midx < 0) { printf("ERROR: Book or Member not found\n"); return; }

    /* Heuristics are decided here but applied to the pool item only after
     * submit_request, since that is where the item actually exists. */
    int suspicious = 0;
    if (count_active_borrows(member_id) >= MAX_CONCURRENT_BORROWS) {
        suspicious = 1;
        printf("FLAGGED SUSPICIOUS: %s already holds the maximum of %d concurrent copies.\n", member_id, MAX_CONCURRENT_BORROWS);
    }
    time_t last_return;
    if (recent_return_time(book_id, member_id, &last_return) && (time(NULL) - last_return) < RAPID_REBORROW_WINDOW_SEC) {
        suspicious = 1;
        printf("FLAGGED SUSPICIOUS: rapid re-borrow of the same title within the watch window.\n");
    }

    /* A copy's state only flips to BORROWED once its request is mined, so
     * without this check two members could both have a pending borrow
     * request queued against the very same still-"AVAILABLE" copy. We
     * guard against that by also excluding any copy that already has an
     * unconfirmed BORROWED/RENEWED request sitting in the pending pool. */
    Copy *target = NULL;
    for (int i = 0; i < g_copy_count; i++)
        if (!strcmp(g_copies[i].book_id, book_id) && g_copies[i].state == ST_RESERVED
            && !strcmp(g_copies[i].holder_id, member_id) && !copy_has_pending_claim(g_copies[i].copy_id))
            { target = &g_copies[i]; break; }
    if (!target)
        for (int i = 0; i < g_copy_count; i++)
            if (!strcmp(g_copies[i].book_id, book_id) && g_copies[i].state == ST_AVAILABLE
                && !copy_has_pending_claim(g_copies[i].copy_id)) { target = &g_copies[i]; break; }

    if (!target) {
        printf("No copy of '%s' is available right now. Use reserve_book to join the queue.\n", book->title);
        return;
    }

    time_t due = time(NULL) + LOAN_PERIOD_SECONDS;
    int idx;
    if (submit_request(book_id, target->copy_id, member_id, "BORROWED", due, 0, 0, NULL, 1, time(NULL), &idx)) {
        if (suspicious) snprintf(g_pool.items[idx].status, sizeof(g_pool.items[idx].status), "SUSPICIOUS");
        printf("OK: borrow request for '%s' (copy %s) queued for %s. Status: %s.\n",
               book->title, target->copy_id, member_id, g_pool.items[idx].status);
    }
}

static void cmd_return_book(const char *copy_id, const char *member_id, const char *new_condition, const char *override_reason) {
    Copy *copy = find_copy(copy_id);
    int midx = find_member_idx(member_id);
    if (!copy || midx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    if (copy->state != ST_BORROWED || strcmp(copy->holder_id, member_id) != 0) {
        printf("ERROR: no active loan of copy '%s' by %s.\n", copy_id, member_id);
        return;
    }
    Book *book = find_book(copy->book_id);
    time_t now = time(NULL);
    int late = now > copy->due_date;
    int fine = compute_fine(copy->due_date, now);

    /* Condition-manipulation heuristic: downgrading more than one level
     * (e.g. NEW straight to LOST) without an override reason gets flagged.
     * We only decide that here; the copy's recorded condition itself is
     * NOT changed until the return is actually mined (apply_confirmed_record
     * below), same as every other field a return affects. */
    int condition_suspicious = 0;
    Condition newc = copy->condition;
    if (new_condition) {
        newc = COND_GOOD;
        if (!strcmp(new_condition, "NEW")) newc = COND_NEW;
        else if (!strcmp(new_condition, "GOOD")) newc = COND_GOOD;
        else if (!strcmp(new_condition, "WORN")) newc = COND_WORN;
        else if (!strcmp(new_condition, "LOST")) newc = COND_LOST;
        if ((int)newc - (int)copy->condition > 1 && (!override_reason || !override_reason[0])) {
            condition_suspicious = 1;
            printf("FLAGGED SUSPICIOUS: condition dropped more than one level with no override reason code.\n");
        }
    }

    int reward = late ? LATE_REWARD : ON_TIME_REWARD;
    char raw[128], tx[65];
    snprintf(raw, sizeof(raw), "%s|%s|%d|%ld", member_id, copy->book_id, reward, (long)now);
    sha256_hex((unsigned char *)raw, strlen(raw), tx);

    int idx;
    if (submit_request(copy->book_id, copy_id, member_id, "RETURNED", copy->due_date, fine, reward, tx, 0, copy->due_date, &idx)) {
        if (condition_suspicious) snprintf(g_pool.items[idx].status, sizeof(g_pool.items[idx].status), "SUSPICIOUS");
        if (new_condition) g_pool.items[idx].reported_condition = (int)newc;
        printf("OK: return of '%s' (copy %s) queued, %s%s. Reward %d queued, fine %d. Status: %s.\n",
               book ? book->title : copy->book_id, copy_id, late ? "LATE" : "ON TIME",
               fine > 0 ? ", fine owed" : "", reward, fine, g_pool.items[idx].status);
    }
}

static void cmd_reserve_book(const char *book_id, const char *member_id) {
    Book *book = find_book(book_id);
    int midx = find_member_idx(member_id);
    if (!book || midx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    int bidx = find_book_idx(book_id);
    int idx;
    if (submit_request(book_id, "-", member_id, "RESERVED", 0, 0, 0, NULL, 1, time(NULL), &idx)) {
        enqueue_reservation(bidx, member_id);
        printf("OK: %s added to the reservation queue for '%s'. Status: %s.\n", member_id, book->title, g_pool.items[idx].status);
    }
}

static void cmd_renew_book(const char *copy_id, const char *member_id) {
    Copy *copy = find_copy(copy_id);
    int midx = find_member_idx(member_id);
    if (!copy || midx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    if (copy->state != ST_BORROWED || strcmp(copy->holder_id, member_id) != 0) {
        printf("ERROR: no active loan of copy '%s' by %s.\n", copy_id, member_id); return;
    }
    int bidx = find_book_idx(copy->book_id);
    if (g_res_head[bidx]) { printf("ERROR: cannot renew, another member is waiting in the reservation queue.\n"); return; }
    if (copy->renewals_used >= MAX_RENEWALS) { printf("ERROR: maximum renewals (%d) already used for this copy.\n", MAX_RENEWALS); return; }

    time_t new_due = copy->due_date + RENEWAL_PERIOD_SECONDS;
    int idx;
    if (submit_request(copy->book_id, copy_id, member_id, "RENEWED", new_due, 0, 0, NULL, 1, time(NULL), &idx)) {
        printf("OK: renewal of copy %s queued, new due date in %d seconds from the old one. Status: %s.\n",
               copy_id, RENEWAL_PERIOD_SECONDS, g_pool.items[idx].status);
    }
}

static void cmd_check_overdue(void) {
    time_t now = time(NULL);
    int any = 0;
    printf("\nOverdue scan:\n");
    for (int i = 0; i < g_copy_count; i++) {
        Copy *c = &g_copies[i];
        if (c->state == ST_BORROWED && now > c->due_date) {
            any = 1;
            int fine = compute_fine(c->due_date, now);
            /* Only add the *increase* since this copy was last scanned, not
             * the full recomputed total — otherwise a member with two
             * overdue copies would have the second scan's flat total
             * overwrite the first's contribution, and a member scanned
             * twice would be charged the same lateness repeatedly. */
            int delta = fine - c->scan_fine_charged;
            if (delta != 0) {
                int midx = find_member_idx(c->holder_id);
                if (midx >= 0) g_member_fine[midx] += delta;
                c->scan_fine_charged = fine;
            }
            Book *b = find_book(c->book_id);
            printf("  OVERDUE: copy %s ('%s') held by %s, fine now %d (running total)\n", c->copy_id, b ? b->title : c->book_id, c->holder_id, fine);
        }
    }
    if (!any) printf("  (nothing overdue)\n");
}

static void cmd_view_fines(void) {
    printf("\nOutstanding fines:\n");
    int any = 0;
    for (int i = 0; i < g_member_count; i++)
        if (g_member_fine[i] > 0) { printf("  %-10s %d\n", g_members[i].member_id, g_member_fine[i]); any = 1; }
    if (!any) printf("  (none)\n");
}

static void cmd_settle_fine(const char *member_id, int amount) {
    int idx = find_member_idx(member_id);
    if (idx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    if (amount > g_member_fine[idx]) { printf("ERROR: that member only owes %d.\n", g_member_fine[idx]); return; }
    int balance = (g_model == MODEL_UTXO) ? utxo_balance(member_id) : find_account(member_id)->balance;
    if (balance < amount) { printf("ERROR: insufficient token balance to settle this fine (%d < %d).\n", balance, amount); return; }
    if (g_model == MODEL_UTXO) {
        /* UTXO payment goes to the library as an ordinary spend (fee applies). */
        if (!utxo_transfer(member_id, "LIBRARY", amount)) return;
    } else {
        /* The library is not a registered member, so there is no account to
         * credit; the payment is simply debited from the member and logged
         * in their history. No transfer fee applies to paying a fine. */
        g_accounts[idx].balance -= amount;
        append_history(&g_accounts[idx], member_id, "LIBRARY", amount, 0, g_member_nonce[idx]);
        g_member_nonce[idx]++;
    }
    g_member_fine[idx] -= amount;
    printf("OK: %s settled %d of their fine. Remaining: %d.\n", member_id, amount, g_member_fine[idx]);
}

static void cmd_mark_lost(const char *copy_id, const char *reason) {
    Copy *c = find_copy(copy_id);
    if (!c) { printf("ERROR: unknown copy.\n"); return; }
    if (!reason || !reason[0]) { printf("ERROR: mark_lost requires a reason code.\n"); return; }
    c->state = ST_LOST; c->condition = COND_LOST;
    printf("OK: copy %s marked LOST (reason: %s).\n", copy_id, reason);
}

/* -------------------------------------------------------------------- */
/* Mining: batches pending items into Merkle-rooted, PoW-sealed blocks   */
/* -------------------------------------------------------------------- */

static int priority_cmp(const void *pa, const void *pb) {
    const PendingItem *a = *(const PendingItem **)pa, *b = *(const PendingItem **)pb;
    if (a->overdue_priority != b->overdue_priority) return a->overdue_priority - b->overdue_priority;
    if (a->priority_date < b->priority_date) return -1;
    if (a->priority_date > b->priority_date) return 1;
    return 0;
}

/* Apply the real-world effects of one confirmed record: copy state
 * transitions, reservation hand-off, ledger reward, fine, and nonce.
 * reported_condition is -1 unless this was a RETURNED record that
 * reported a new condition for the copy, in which case it's only
 * applied here, at confirmation time, not when the return was submitted. */
static void apply_confirmed_record(LendingRecord *r, int reported_condition) {
    Copy *copy = r->copy_id[0] && strcmp(r->copy_id, "-") ? find_copy(r->copy_id) : NULL;
    int midx = find_member_idx(r->member_id);

    if (!strcmp(r->action, "BORROWED") && copy) {
        copy->state = ST_BORROWED;
        snprintf(copy->holder_id, sizeof(copy->holder_id), "%s", r->member_id);
        copy->due_date = r->due_date;
        copy->renewals_used = 0;
        copy->scan_fine_charged = 0;
    } else if (!strcmp(r->action, "RETURNED") && copy) {
        int bidx = find_book_idx(r->book_id);
        char next_member[20];
        if (bidx >= 0 && pop_reservation(bidx, next_member)) {
            copy->state = ST_RESERVED;
            snprintf(copy->holder_id, sizeof(copy->holder_id), "%s", next_member);
            printf("  [reservation] copy %s automatically offered to %s\n", r->copy_id, next_member);
        } else {
            copy->state = ST_AVAILABLE;
            copy->holder_id[0] = '\0';
        }
        /* The return's own fine_amount is the final, authoritative charge
         * for this loan. Any amount check_overdue already added for this
         * same copy while it was still out gets netted off here so the
         * lateness is only ever charged once. */
        if (midx >= 0) {
            int delta = r->fine_amount - copy->scan_fine_charged;
            if (delta != 0) g_member_fine[midx] += delta;
        }
        copy->scan_fine_charged = 0;
        if (reported_condition >= 0) copy->condition = (Condition)reported_condition;
        if (r->token_reward > 0) {
            if (g_model == MODEL_UTXO) credit_utxo_reward(r->member_id, r->token_reward, r->tx_id);
            else credit_account_reward(r->member_id, r->token_reward);
        }
    } else if (!strcmp(r->action, "RENEWED") && copy) {
        copy->due_date = r->due_date;
        copy->renewals_used++;
    }
    /* RESERVED records don't change copy state directly; the queue entry
     * was already added when the request was submitted. */

    if (midx >= 0) g_member_nonce[midx]++;  /* nonce increments only on confirmation */
}

static unsigned long mine_batch(Block *out_block, const char *sealed_by) {
    /* Gather all PENDING (non-suspicious) items and sort by priority. */
    PendingItem *ptrs[4096]; int n = 0;
    for (int i = 0; i < g_pool.count && n < 4096; i++)
        if (!strcmp(g_pool.items[i].status, "PENDING")) ptrs[n++] = &g_pool.items[i];
    if (n == 0) return 0;
    qsort(ptrs, n, sizeof(PendingItem *), priority_cmp);

    int batch_n = n < RECORDS_PER_BLOCK ? n : RECORDS_PER_BLOCK;
    Block b; memset(&b, 0, sizeof(b));
    b.index = g_chain.count;
    b.timestamp = time(NULL);
    if (g_chain.count > 0 && b.timestamp <= g_chain.items[g_chain.count-1].timestamp)
        b.timestamp = g_chain.items[g_chain.count-1].timestamp + 1;
    b.record_count = batch_n;
    for (int i = 0; i < batch_n; i++) b.records[i] = ptrs[i]->rec;
    snprintf(b.previous_hash, sizeof(b.previous_hash), "%s", g_chain.count > 0 ? g_chain.items[g_chain.count-1].hash : "");
    if (g_chain.count == 0) zeros64(b.previous_hash);
    compute_merkle_root(b.records, batch_n, b.merkle_root);
    snprintf(b.sealed_by, sizeof(b.sealed_by), "%s", sealed_by);

    int total_reward = 0;
    char tx_concat[65 * RECORDS_PER_BLOCK + 1] = {0};
    for (int i = 0; i < batch_n; i++) {
        total_reward += b.records[i].token_reward;
        if (b.records[i].token_reward > 0) strncat(tx_concat, b.records[i].tx_id, 64);
    }
    b.token_reward = total_reward;
    if (tx_concat[0]) sha256_hex((unsigned char *)tx_concat, strlen(tx_concat), b.transaction_id);
    else snprintf(b.transaction_id, sizeof(b.transaction_id), "-");

    unsigned long attempts = 0; char hex[65];
    for (b.nonce = 0; ; b.nonce++) {
        attempts++;
        compute_block_pow_hash(&b, hex);
        if (leading_zero_hex(hex, g_difficulty)) { snprintf(b.hash, sizeof(b.hash), "%s", hex); break; }
    }

    for (int i = 0; i < batch_n; i++) apply_confirmed_record(&b.records[i], ptrs[i]->reported_condition);
    chain_append(&b);

    /* Remove the mined items from the pool (by request_id, since pointers
     * can move around once we start deleting). */
    for (int i = 0; i < batch_n; i++) {
        for (int j = 0; j < g_pool.count; j++) {
            if (!strcmp(g_pool.items[j].rec.record_id, b.records[i].record_id)) { pool_remove_at(j); break; }
        }
    }

    if (out_block) *out_block = b;
    return attempts;
}

static void cmd_mine_solo(void) {
    if (g_pool.count == 0) { printf("Nothing pending to mine.\n"); return; }
    unsigned long total = 0; int blocks = 0;
    for (;;) {
        Block mined;
        unsigned long a = mine_batch(&mined, "SOLO");
        if (a == 0) break;
        total += a; blocks++;
        printf("Block #%d sealed by SOLO: %d record(s), %lu attempts, hash %.16s...\n",
               mined.index, mined.record_count, a, mined.hash);
    }
    printf("Mined %d block(s), %lu total attempts, solo reward %d (reported only).\n", blocks, total, blocks * SOLO_BLOCK_REWARD);
}

static void cmd_mine_pool(int num_miners) {
    if (g_pool.count == 0) { printf("Nothing pending to mine.\n"); return; }
    if (num_miners < 2) num_miners = 2;
    if (num_miners > 6) num_miners = 6;
    unsigned long total = 0; int blocks = 0;
    for (;;) {
        Block mined;
        unsigned long a = mine_batch(&mined, "POOL");
        if (a == 0) break;
        total += a; blocks++;
    }
    if (blocks == 0) { printf("Nothing pending to mine.\n"); return; }
    int reward_total = blocks * SOLO_BLOCK_REWARD;
    double fee = reward_total * (POOL_FEE_PERCENT / 100.0), net = reward_total - fee;
    int w[6], sw = 0;
    for (int i = 0; i < num_miners; i++) { w[i] = (rand()%100)+1; sw += w[i]; }
    printf("Mined %d block(s), %lu total attempts. Reward pool %d, fee %.2f, net %.2f\n", blocks, total, reward_total, fee, net);
    printf("\n%-10s %-12s %-10s %s\n", "MINER", "ATTEMPTS", "SHARE %", "REWARD");
    for (int i = 0; i < num_miners; i++)
        printf("miner_%-4d %-12lu %-10.2f %.2f\n", i+1, (unsigned long)((double)total*w[i]/sw), 100.0*w[i]/sw, net*w[i]/sw);
}

static void cmd_mine_cloud(int rounds) {
    if (rounds < 1) rounds = 1;
    if (rounds > 5) rounds = 5;
    int gross = 0, fees = 0;
    printf("\n--- Cloud mining: %d round(s) ---\n", rounds);
    for (int r = 1; r <= rounds; r++) {
        fees += CLOUD_RENTAL_FEE;
        int reward = 0;
        Block mined;
        unsigned long a = mine_batch(&mined, "CLOUD");
        if (a > 0) {
            reward = 2 + rand()%14;
            printf("Round %d: mined block #%d (%d records) in %lu attempts. Fee -%d, reward +%d.\n",
                   r, mined.index, mined.record_count, a, CLOUD_RENTAL_FEE, reward);
        } else printf("Round %d: nothing pending. Fee -%d, reward +0.\n", r, CLOUD_RENTAL_FEE);
        gross += reward;
        if (fees > gross) printf("  WARNING: cumulative fees (%d) exceed cumulative rewards (%d).\n", fees, gross);
    }
    printf("\nSummary: gross %d, fees %d, net %d.\n", gross, fees, gross - fees);
}

/* -------------------------------------------------------------------- */
/* Chain validation                                                       */
/* -------------------------------------------------------------------- */

static int validate_chain(int verbose) {
    int ok = 1;
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.items[i];
        char recomputed_hash[65]; compute_block_pow_hash(b, recomputed_hash);
        int hash_ok = !strcmp(recomputed_hash, b->hash);
        int pow_ok = leading_zero_hex(b->hash, g_difficulty <= 4 ? 1 : 1); (void)pow_ok;

        char recomputed_merkle[65]; compute_merkle_root(b->records, b->record_count, recomputed_merkle);
        int merkle_ok = !strcmp(recomputed_merkle, b->merkle_root);

        int link_ok;
        if (i > 0) link_ok = !strcmp(b->previous_hash, g_chain.items[i-1].hash);
        else { char z[65]; zeros64(z); link_ok = !strcmp(b->previous_hash, z); }

        int ts_ok = (i == 0) || (b->timestamp > g_chain.items[i-1].timestamp);

        int sig_ok = 1;
        for (int j = 0; j < b->record_count; j++) if (!verify_record_signature(&b->records[j])) sig_ok = 0;

        if (verbose)
            printf("Block #%-3d hash:%s merkle:%s link:%s timestamp:%s signatures:%s\n",
                   b->index, hash_ok?"OK":"MISMATCH", merkle_ok?"OK":"MISMATCH", link_ok?"OK":"BROKEN",
                   ts_ok?"OK":"BAD", sig_ok?"VALID":"INVALID");
        if (!hash_ok || !merkle_ok || !link_ok || !sig_ok || !ts_ok) ok = 0;
    }
    return ok;
}

/* -------------------------------------------------------------------- */
/* Views                                                                  */
/* -------------------------------------------------------------------- */

static void print_record_row(LendingRecord *r) {
    printf("  %-8s %-8s %-20.20s %-10s %-10s reward:%-3d fine:%-3d nonce:%lu sig:%s\n",
           r->action, r->copy_id, r->book_title, r->member_id, r->action, r->token_reward, r->fine_amount,
           r->nonce, verify_record_signature(r) ? "valid" : "INVALID");
}

static void cmd_chain_view(void) {
    printf("\nConfirmed chain (%d block(s)):\n", g_chain.count);
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.items[i];
        printf("Block #%d | sealed by %s | %d record(s) | merkle %.10s... | hash %.10s...\n",
               b->index, b->sealed_by, b->record_count, b->merkle_root, b->hash);
        for (int j = 0; j < b->record_count; j++) print_record_row(&b->records[j]);
    }
}

static void cmd_pool_view(void) {
    printf("\nPending pool (%d item(s)):\n", g_pool.count);
    for (int i = 0; i < g_pool.count; i++) {
        PendingItem *p = &g_pool.items[i];
        printf("  [%d] %-10s %-8s copy:%-8s member:%-10s priority:%d status:%s\n",
               i, p->rec.action, p->rec.book_id, p->rec.copy_id, p->rec.member_id, p->overdue_priority, p->status);
    }
}

static void cmd_fraud_review(void) {
    printf("\nSuspicious requests awaiting review:\n");
    int any = 0;
    for (int i = 0; i < g_pool.count; i++)
        if (!strcmp(g_pool.items[i].status, "SUSPICIOUS")) {
            any = 1;
            printf("  [%d] %-10s %-8s member:%-10s request_id:%.12s...\n",
                   i, g_pool.items[i].rec.action, g_pool.items[i].rec.book_id, g_pool.items[i].rec.member_id, g_pool.items[i].rec.record_id);
        }
    if (!any) printf("  (none)\n");
}

static void cmd_lending_history(const char *filter_member, const char *filter_book) {
    printf("\nLending history:\n");
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.items[i];
        for (int j = 0; j < b->record_count; j++) {
            LendingRecord *r = &b->records[j];
            if (filter_member && strcmp(r->member_id, filter_member)) continue;
            if (filter_book && strcmp(r->book_id, filter_book)) continue;
            printf("  block #%-3d %-10s %-8s %-20.20s member:%-10s\n", b->index, r->action, r->copy_id, r->book_title, r->member_id);
        }
    }
}

/* -------------------------------------------------------------------- */
/* Persistence                                                            */
/* -------------------------------------------------------------------- */

static void save_record_line(FILE *f, LendingRecord *r) {
    char sig_hex[SIG_MAX_LEN*2+1]; bytes_to_hex(r->signature, r->siglen, sig_hex);
    fprintf(f, "%s|%s|%s|%s|%s|%s|%s|%ld|%ld|%d|%d|%s|%lu|%u|%s\n",
            r->record_id, r->book_id, r->copy_id, r->book_title, r->member_id, r->member_name, r->action,
            (long)r->timestamp, (long)r->due_date, r->fine_amount, r->token_reward, r->tx_id, r->nonce, r->siglen, sig_hex);
}
static int load_record_line(char *line, LendingRecord *r) {
    char *f[15]; int n = 0; char *tok = strtok(line, "|");
    while (tok && n < 15) { f[n++] = tok; tok = strtok(NULL, "|"); }
    if (n != 15) return 0;
    snprintf(r->record_id, sizeof(r->record_id), "%s", f[0]);
    snprintf(r->book_id, sizeof(r->book_id), "%s", f[1]);
    snprintf(r->copy_id, sizeof(r->copy_id), "%s", f[2]);
    snprintf(r->book_title, sizeof(r->book_title), "%s", f[3]);
    snprintf(r->member_id, sizeof(r->member_id), "%s", f[4]);
    snprintf(r->member_name, sizeof(r->member_name), "%s", f[5]);
    snprintf(r->action, sizeof(r->action), "%s", f[6]);
    r->timestamp = (time_t)atol(f[7]); r->due_date = (time_t)atol(f[8]);
    r->fine_amount = atoi(f[9]); r->token_reward = atoi(f[10]);
    snprintf(r->tx_id, sizeof(r->tx_id), "%s", f[11]);
    r->nonce = strtoul(f[12], NULL, 10);
    r->siglen = (unsigned int)atoi(f[13]);
    hex_to_bytes(f[14], r->signature, SIG_MAX_LEN);
    return 1;
}

static void save_chain(void) {
    FILE *f = fopen(CHAIN_FILE, "w"); if (!f) return;
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.items[i];
        fprintf(f, "BLOCK|%d|%ld|%d|%s|%s|%s|%d|%s|%lu|%s\n",
                b->index, (long)b->timestamp, b->record_count, b->previous_hash, b->merkle_root,
                b->sealed_by, b->token_reward, b->transaction_id, b->nonce, b->hash);
        for (int j = 0; j < b->record_count; j++) save_record_line(f, &b->records[j]);
    }
    fclose(f);
}
static void load_chain(void) {
    FILE *f = fopen(CHAIN_FILE, "r"); if (!f) return;
    char line[1024];
    Block cur; int have_block = 0;
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line); if (!line[0]) continue;
        if (!strncmp(line, "BLOCK|", 6)) {
            if (have_block) chain_append(&cur);
            memset(&cur, 0, sizeof(cur));
            char *f2[10]; int n = 0; char *tok = strtok(line, "|"); /* consumes "BLOCK" */
            tok = strtok(NULL, "|");
            while (tok && n < 10) { f2[n++] = tok; tok = strtok(NULL, "|"); }
            if (n == 10) {
                cur.index = atoi(f2[0]); cur.timestamp = (time_t)atol(f2[1]); cur.record_count = atoi(f2[2]);
                snprintf(cur.previous_hash, sizeof(cur.previous_hash), "%s", f2[3]);
                snprintf(cur.merkle_root, sizeof(cur.merkle_root), "%s", f2[4]);
                snprintf(cur.sealed_by, sizeof(cur.sealed_by), "%s", f2[5]);
                cur.token_reward = atoi(f2[6]);
                snprintf(cur.transaction_id, sizeof(cur.transaction_id), "%s", f2[7]);
                cur.nonce = strtoul(f2[8], NULL, 10);
                snprintf(cur.hash, sizeof(cur.hash), "%s", f2[9]);
                have_block = 1;
            }
        } else if (have_block && cur.record_count > 0) {
            static int rec_i = 0;
            LendingRecord r;
            if (load_record_line(line, &r)) cur.records[rec_i++] = r;
            if (rec_i >= cur.record_count) rec_i = 0;
        }
    }
    if (have_block) chain_append(&cur);
    fclose(f);
}

static void save_copies(void) {
    FILE *f = fopen(COPY_STATE_FILE, "w"); if (!f) return;
    for (int i = 0; i < g_copy_count; i++) {
        Copy *c = &g_copies[i];
        fprintf(f, "%s|%s|%d|%d|%s|%ld|%d\n", c->copy_id, c->book_id, c->condition, c->state, c->holder_id, (long)c->due_date, c->renewals_used);
    }
    fclose(f);
}
static void load_copy_state(void) {
    FILE *f = fopen(COPY_STATE_FILE, "r"); if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line); if (!line[0]) continue;
        char *fd[7]; int n = 0; char *tok = strtok(line, "|");
        while (tok && n < 7) { fd[n++] = tok; tok = strtok(NULL, "|"); }
        if (n != 7) continue;
        Copy *c = find_copy(fd[0]); if (!c) continue;
        c->condition = (Condition)atoi(fd[2]); c->state = (CopyState)atoi(fd[3]);
        snprintf(c->holder_id, sizeof(c->holder_id), "%s", fd[4]);
        c->due_date = (time_t)atol(fd[5]); c->renewals_used = atoi(fd[6]);
    }
    fclose(f);
}

static void save_reservations(void) {
    FILE *f = fopen(RESERVE_FILE, "w"); if (!f) return;
    for (int i = 0; i < g_book_count; i++)
        for (ResNode *n = g_res_head[i]; n; n = n->next)
            fprintf(f, "%s|%s|%ld\n", g_books[i].book_id, n->member_id, (long)n->reservation_date);
    fclose(f);
}
static void load_reservations(void) {
    FILE *f = fopen(RESERVE_FILE, "r"); if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line); if (!line[0]) continue;
        char *book = strtok(line, "|"), *member = strtok(NULL, "|"), *date = strtok(NULL, "|");
        if (!book || !member || !date) continue;
        int bidx = find_book_idx(book); if (bidx < 0) continue;
        ResNode *n = malloc(sizeof(ResNode));
        snprintf(n->member_id, sizeof(n->member_id), "%s", member);
        n->reservation_date = (time_t)atol(date); n->next = NULL;
        if (!g_res_head[bidx]) g_res_head[bidx] = n; else g_res_tail[bidx]->next = n;
        g_res_tail[bidx] = n;
    }
    fclose(f);
}

static void save_pool(void) {
    FILE *f = fopen(POOL_FILE, "w"); if (!f) return;
    for (int i = 0; i < g_pool.count; i++) {
        PendingItem *p = &g_pool.items[i];
        fprintf(f, "ITEM|%s|%d|%ld\n", p->status, p->overdue_priority, (long)p->priority_date);
        save_record_line(f, &p->rec);
    }
    fclose(f);
}
static void load_pool(void) {
    FILE *f = fopen(POOL_FILE, "r"); if (!f) return;
    char line[1024];
    PendingItem cur; int have = 0;
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line); if (!line[0]) continue;
        if (!strncmp(line, "ITEM|", 5)) {
            if (have) pool_append(&cur);
            memset(&cur, 0, sizeof(cur));
            strtok(line, "|"); /* discard the "ITEM" tag */
            char *status = strtok(NULL, "|"), *prio = strtok(NULL, "|"), *date = strtok(NULL, "|");
            if (status) snprintf(cur.status, sizeof(cur.status), "%s", status);
            if (prio) cur.overdue_priority = atoi(prio);
            if (date) cur.priority_date = (time_t)atol(date);
            have = 1;
        } else if (have) {
            load_record_line(line, &cur.rec);
            pool_append(&cur);
            have = 0;
        }
    }
    fclose(f);
}

static void save_utxos(void) {
    FILE *f = fopen(UTXO_FILE, "w"); if (!f) return;
    for (int i = 0; i < g_utxo_count; i++) {
        UTXO *u = &g_utxos[i];
        fprintf(f, "%s|%d|%s|%d|%d\n", u->tx_id, u->output_index, u->owner, u->amount, u->spent);
    }
    fclose(f);
}
static void load_utxos(void) {
    FILE *f = fopen(UTXO_FILE, "r"); if (!f) return;
    char line[160];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line); if (!line[0]) continue;
        char *fd[5]; int n = 0; char *tok = strtok(line, "|");
        while (tok && n < 5) { fd[n++] = tok; tok = strtok(NULL, "|"); }
        if (n != 5 || g_utxo_count >= MAX_UTXO) continue;
        UTXO *u = &g_utxos[g_utxo_count++];
        snprintf(u->tx_id, sizeof(u->tx_id), "%s", fd[0]); u->output_index = atoi(fd[1]);
        snprintf(u->owner, sizeof(u->owner), "%s", fd[2]); u->amount = atoi(fd[3]); u->spent = atoi(fd[4]);
    }
    fclose(f);
}

static void save_accounts(void) {
    FILE *f = fopen(ACCOUNTS_FILE, "w"); if (!f) return;
    for (int i = 0; i < g_member_count; i++) fprintf(f, "%s|%d\n", g_accounts[i].member_id, g_accounts[i].balance);
    fclose(f);
}
static void load_accounts(void) {
    FILE *f = fopen(ACCOUNTS_FILE, "r"); if (!f) return;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line); if (!line[0]) continue;
        char *id = strtok(line, "|"), *bal = strtok(NULL, "|");
        if (!id || !bal) continue;
        Account *a = find_account(id); if (a) a->balance = atoi(bal);
    }
    fclose(f);
}

static void save_nonces_and_fines(void) {
    FILE *f = fopen(NONCES_FILE, "w");
    if (f) { for (int i = 0; i < g_member_count; i++) fprintf(f, "%s|%lu\n", g_members[i].member_id, g_member_nonce[i]); fclose(f); }
    FILE *f2 = fopen(FINES_FILE, "w");
    if (f2) { for (int i = 0; i < g_member_count; i++) fprintf(f2, "%s|%d\n", g_members[i].member_id, g_member_fine[i]); fclose(f2); }
}
static void load_nonces_and_fines(void) {
    FILE *f = fopen(NONCES_FILE, "r");
    if (f) {
        char line[64];
        while (fgets(line, sizeof(line), f)) {
            trim_newline(line); if (!line[0]) continue;
            char *id = strtok(line, "|"), *n = strtok(NULL, "|");
            if (!id || !n) continue;
            int idx = find_member_idx(id); if (idx >= 0) g_member_nonce[idx] = strtoul(n, NULL, 10);
        }
        fclose(f);
    }
    FILE *f2 = fopen(FINES_FILE, "r");
    if (f2) {
        char line[64];
        while (fgets(line, sizeof(line), f2)) {
            trim_newline(line); if (!line[0]) continue;
            char *id = strtok(line, "|"), *amt = strtok(NULL, "|");
            if (!id || !amt) continue;
            int idx = find_member_idx(id); if (idx >= 0) g_member_fine[idx] = atoi(amt);
        }
        fclose(f2);
    }
}

static void save_meta(void) {
    FILE *f = fopen(META_FILE, "w"); if (!f) return;
    fprintf(f, "difficulty=%d\nmodel=%d\n", g_difficulty, (int)g_model);
    fclose(f);
}
static void load_meta(void) {
    FILE *f = fopen(META_FILE, "r"); if (!f) return;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        if (!strncmp(line, "difficulty=", 11)) g_difficulty = atoi(line+11);
    }
    fclose(f);
}

static void cmd_chain_save(void) {
    save_chain(); save_copies(); save_reservations(); save_pool();
    save_utxos(); save_accounts(); save_nonces_and_fines(); save_meta();
    printf("OK: full state saved to disk.\n");
}
static void cmd_chain_load(void) {
    g_chain.count = 0; g_pool.count = 0; g_utxo_count = 0;
    load_chain(); load_copy_state(); load_reservations(); load_pool();
    load_utxos(); load_accounts(); load_nonces_and_fines(); load_meta();
    printf("OK: state reloaded from disk. Re-validating...\n");
    g_chain_was_valid_on_load = validate_chain(1);
    printf("Chain status after reload: %s\n", g_chain_was_valid_on_load ? "VALID" : "INVALID — review before trusting this session");
}

/* -------------------------------------------------------------------- */
/* Tamper demo (kept from Formative 1/2, adapted to batched blocks)      */
/* -------------------------------------------------------------------- */

static void cmd_tamper_demo(int block_idx) {
    if (block_idx < 0 || block_idx >= g_chain.count || g_chain.items[block_idx].record_count == 0) {
        printf("ERROR: invalid block index.\n"); return;
    }
    printf("\n--- BEFORE tampering ---\n"); validate_chain(1);
    int old = g_chain.items[block_idx].records[0].fine_amount;
    g_chain.items[block_idx].records[0].fine_amount = old == 999 ? 0 : 999;
    printf("\n[Changed block #%d's first record fine_amount without re-mining or re-signing]\n", block_idx);
    printf("\n--- AFTER tampering ---\n");
    int ok = validate_chain(1);
    printf("\nResult: %s\n", ok ? "VALID" : "TAMPERING DETECTED");
    g_chain.items[block_idx].records[0].fine_amount = old;
}

/* -------------------------------------------------------------------- */
/* register_member / register_book / add_copy / view_* / help            */
/* -------------------------------------------------------------------- */

static void cmd_register_member(const char *id, const char *name, const char *course) {
    if (find_member_idx(id) >= 0) { printf("ERROR: member already exists.\n"); return; }
    if (g_member_count >= MAX_MEMBERS) { printf("ERROR: registry full.\n"); return; }
    Member *m = &g_members[g_member_count];
    snprintf(m->member_id, sizeof(m->member_id), "%s", id);
    snprintf(m->full_name, sizeof(m->full_name), "%s", name);
    snprintf(m->course_code, sizeof(m->course_code), "%s", course);
    g_member_keys[g_member_count] = generate_member_key();
    set_pubkey_hex(g_member_count);
    g_member_nonce[g_member_count] = 0; g_member_fine[g_member_count] = 0;
    snprintf(g_accounts[g_member_count].member_id, sizeof(g_accounts[g_member_count].member_id), "%s", id);
    g_accounts[g_member_count].balance = 0; g_accounts[g_member_count].history = NULL;
    g_member_count++;
    save_member_keys();
    printf("OK: registered member %s with a new signing key.\n", id);
}

static void cmd_register_book(const char *id, const char *title, const char *author) {
    if (find_book(id)) { printf("ERROR: book already exists.\n"); return; }
    if (g_book_count >= MAX_BOOKS) { printf("ERROR: registry full.\n"); return; }
    Book *b = &g_books[g_book_count++];
    snprintf(b->book_id, sizeof(b->book_id), "%s", id);
    snprintf(b->title, sizeof(b->title), "%s", title);
    snprintf(b->author, sizeof(b->author), "%s", author);
    printf("OK: registered book %s.\n", id);
}

static void cmd_add_copy(const char *copy_id, const char *book_id, const char *condition) {
    if (!find_book(book_id)) { printf("ERROR: Book or Member not found\n"); return; }
    if (find_copy(copy_id)) { printf("ERROR: copy already exists.\n"); return; }
    if (g_copy_count >= MAX_COPIES) { printf("ERROR: copy table full.\n"); return; }
    Copy *c = &g_copies[g_copy_count++];
    snprintf(c->copy_id, sizeof(c->copy_id), "%s", copy_id);
    snprintf(c->book_id, sizeof(c->book_id), "%s", book_id);
    c->condition = COND_NEW;
    if (condition) {
        if (!strcmp(condition, "GOOD")) c->condition = COND_GOOD;
        else if (!strcmp(condition, "WORN")) c->condition = COND_WORN;
    }
    c->state = ST_AVAILABLE; c->holder_id[0] = '\0'; c->due_date = 0; c->renewals_used = 0;
    printf("OK: added copy %s of %s.\n", copy_id, book_id);
}

static void cmd_view_member(const char *id) {
    int idx = find_member_idx(id);
    if (idx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    printf("\nMember %s: %s (%s)\nPublic key: %.32s...\nNonce: %lu  Fine owed: %d\n",
           g_members[idx].member_id, g_members[idx].full_name, g_members[idx].course_code,
           g_member_pubkey_hex[idx], g_member_nonce[idx], g_member_fine[idx]);
}
static void cmd_view_book(const char *id) {
    Book *b = find_book(id);
    if (!b) { printf("ERROR: Book or Member not found\n"); return; }
    printf("\nBook %s: '%s' by %s\nCopies:\n", b->book_id, b->title, b->author);
    for (int i = 0; i < g_copy_count; i++)
        if (!strcmp(g_copies[i].book_id, id))
            printf("  %s  condition:%-5s state:%-10s holder:%s\n", g_copies[i].copy_id,
                   COND_NAME[g_copies[i].condition], STATE_NAME[g_copies[i].state],
                   g_copies[i].holder_id[0] ? g_copies[i].holder_id : "-");
}
static void cmd_view_copy(const char *id) {
    Copy *c = find_copy(id);
    if (!c) { printf("ERROR: unknown copy.\n"); return; }
    printf("\nCopy %s of %s: condition %s, state %s, holder %s\n", c->copy_id, c->book_id,
           COND_NAME[c->condition], STATE_NAME[c->state], c->holder_id[0] ? c->holder_id : "-");
}
static void cmd_reservation_status(const char *book_id) {
    int bidx = find_book_idx(book_id);
    if (bidx < 0) { printf("ERROR: Book or Member not found\n"); return; }
    printf("\nReservation queue for %s:\n", book_id);
    int any = 0;
    for (ResNode *n = g_res_head[bidx]; n; n = n->next) { printf("  %s\n", n->member_id); any = 1; }
    if (!any) printf("  (empty)\n");
}

static void print_help(void) {
    printf(
"\nCommands:\n"
"  register_member <id> <name> <course>      register_book <id> <title> <author>\n"
"  view_member <id>                          view_book <id>\n"
"  member_nonce <id>                         add_copy <copy_id> <book_id> [condition]\n"
"  view_copy <copy_id>                       mark_lost <copy_id> <reason>\n"
"  borrow_book <book_id> <member_id>         return_book <copy_id> <member_id> [condition] [override_reason]\n"
"  renew_book <copy_id> <member_id>          reserve_book <book_id> <member_id>\n"
"  reservation_status <book_id>\n"
"  check_overdue                             view_fines\n"
"  settle_fine <member_id> <amount>\n"
"  token_transfer <from> <to> <amount>       token_balance <member_id>\n"
"  utxo_view                                 account_balance [member_id]\n"
"  account_transfer <from> <to> <amount>     account_nonce <member_id>\n"
"  transaction_history <member_id>\n"
"  pool_view                                 mine_solo\n"
"  mine_pool <num_miners>                    mine_cloud <rounds>\n"
"  chain_view                                validate_chain\n"
"  chain_save                                chain_load\n"
"  difficulty_status                         set_difficulty <1-4>\n"
"  fraud_review                              approve_suspicious <pool_index>\n"
"  reject_suspicious <pool_index>\n"
"  lending_history [member_id]               member_history <member_id>\n"
"  book_history <book_id>                    tamper_demo <block_index>\n"
"  simulate_replay <member_id>               (extra, not required: demonstrates nonce-reuse rejection)\n"
"  help                                      exit\n");
}

/* -------------------------------------------------------------------- */
/* CLI dispatch                                                          */
/* -------------------------------------------------------------------- */

static char *next_tok(void) { return strtok(NULL, " \t"); }


/* -------------------------------------------------------------------- */
/* Numbered menu                                                         */
/* -------------------------------------------------------------------- */
/* The menu is a friendlier front end to the typed commands: it asks for
 * each argument, builds the command line, and hands it to the same
 * dispatcher below. Typing a command name directly still works too. */

typedef struct {
    const char *section;    /* heading printed when it changes */
    const char *cmd;        /* command name the dispatcher understands */
    const char *label;      /* text shown in the menu */
    int nargs;
    const char *prompts[4];
    int optional_from;      /* args at/after this index may be left blank */
} MenuItem;

static const MenuItem MENU[] = {
    {"Members",          "register_member",    "Register a member",              3, {"Member ID", "Full name (no spaces, use _)", "Course code"}, 99},
    {"Members",          "view_member",        "View a member",                  1, {"Member ID"}, 99},
    {"Members",          "member_nonce",       "View a member's nonce",          1, {"Member ID"}, 99},
    {"Books and copies", "register_book",      "Register a book",                3, {"Book ID", "Title (no spaces, use _)", "Author (no spaces, use _)"}, 99},
    {"Books and copies", "view_book",          "View a book and its copies",     1, {"Book ID"}, 99},
    {"Books and copies", "add_copy",           "Add a copy of a book",           3, {"Copy ID", "Book ID", "Condition NEW/GOOD/WORN"}, 2},
    {"Books and copies", "view_copy",          "View a copy",                    1, {"Copy ID"}, 99},
    {"Books and copies", "mark_lost",          "Mark a copy as lost",            2, {"Copy ID", "Reason code"}, 99},
    {"Lending",          "borrow_book",        "Borrow a book",                  2, {"Book ID", "Member ID"}, 99},
    {"Lending",          "return_book",        "Return a book",                  4, {"Copy ID", "Member ID", "Reported condition (blank to skip)", "Override reason (blank to skip)"}, 2},
    {"Lending",          "renew_book",         "Renew a book",                   2, {"Copy ID", "Member ID"}, 99},
    {"Lending",          "reserve_book",       "Reserve a book",                 2, {"Book ID", "Member ID"}, 99},
    {"Lending",          "reservation_status", "View a reservation queue",       1, {"Book ID"}, 99},
    {"Fines",            "check_overdue",      "Check overdue copies",           0, {0}, 99},
    {"Fines",            "view_fines",         "View outstanding fines",         0, {0}, 99},
    {"Fines",            "settle_fine",        "Settle a fine",                  2, {"Member ID", "Amount"}, 99},
    {"Tokens",           "token_transfer",     "Transfer tokens",                3, {"From member ID", "To member ID", "Amount"}, 99},
    {"Tokens",           "token_balance",      "View a token balance",           1, {"Member ID"}, 99},
    {"Tokens",           "utxo_view",          "View the UTXO set",              0, {0}, 99},
    {"Tokens",           "account_balance",    "View account balances",          1, {"Member ID (blank for all)"}, 0},
    {"Tokens",           "account_nonce",      "View an account nonce",          1, {"Member ID"}, 99},
    {"Tokens",           "transaction_history","View a transaction history",     1, {"Member ID"}, 99},
    {"Mining and chain", "pool_view",          "View the pending pool",          0, {0}, 99},
    {"Mining and chain", "mine_solo",          "Mine: solo",                     0, {0}, 99},
    {"Mining and chain", "mine_pool",          "Mine: pool",                     1, {"Number of simulated miners (2-6)"}, 99},
    {"Mining and chain", "mine_cloud",         "Mine: cloud",                    1, {"Rental rounds (1-5)"}, 99},
    {"Mining and chain", "chain_view",         "View the chain",                 0, {0}, 99},
    {"Mining and chain", "validate_chain",     "Validate the chain",             0, {0}, 99},
    {"Mining and chain", "chain_save",         "Save to disk",                   0, {0}, 99},
    {"Mining and chain", "chain_load",         "Load from disk",                 0, {0}, 99},
    {"Mining and chain", "difficulty_status",  "View mining difficulty",         0, {0}, 99},
    {"Mining and chain", "set_difficulty",     "Set mining difficulty",          1, {"Difficulty (1-4)"}, 99},
    {"Fraud and audit",  "fraud_review",       "Review suspicious requests",     0, {0}, 99},
    {"Fraud and audit",  "approve_suspicious", "Approve a suspicious request",   1, {"Item number"}, 99},
    {"Fraud and audit",  "reject_suspicious",  "Reject a suspicious request",    1, {"Item number"}, 99},
    {"Fraud and audit",  "lending_history",    "View the full lending history",  0, {0}, 99},
    {"Fraud and audit",  "member_history",     "View a member's history",        1, {"Member ID"}, 99},
    {"Fraud and audit",  "book_history",       "View a book's history",          1, {"Book ID"}, 99},
    {"Extras",           "tamper_demo",        "Tamper-detection demo",          1, {"Block index to tamper with"}, 99},
    {"Extras",           "simulate_replay",    "Nonce replay demo",              1, {"Member ID"}, 99},
};
#define MENU_COUNT ((int)(sizeof(MENU) / sizeof(MENU[0])))

static void print_menu(void) {
    const char *last = "";
    printf("\n===== Library Blockchain Lending Tracker =====\n");
    printf("Ledger model: %s | Difficulty: %d\n", g_model == MODEL_UTXO ? "UTXO" : "Account", g_difficulty);
    for (int i = 0; i < MENU_COUNT; i++) {
        if (strcmp(last, MENU[i].section) != 0) { printf("-- %s --\n", MENU[i].section); last = MENU[i].section; }
        printf("%2d. %s\n", i + 1, MENU[i].label);
    }
    printf(" 0. Exit\n");
}

/* Reads one menu choice (or a typed command) and writes the resulting
 * command line into `line`. Returns 0 only when input has ended. */
static int read_menu_command(char *line, size_t size) {
    char in[256];
    for (;;) {
        printf("\nChoose an option (m = show menu, 0 = exit): ");
        if (!fgets(in, sizeof(in), stdin)) return 0;
        trim_newline(in);
        if (!in[0]) continue;
        if (in[0] == 'm' && in[1] == '\0') { print_menu(); continue; }
        if (!isdigit((unsigned char)in[0])) { snprintf(line, size, "%s", in); return 1; } /* typed command */

        int choice = atoi(in);
        if (choice == 0) { snprintf(line, size, "quit"); return 1; }
        if (choice < 1 || choice > MENU_COUNT) { printf("Unknown option.\n"); continue; }

        const MenuItem *m = &MENU[choice - 1];
        snprintf(line, size, "%s", m->cmd);
        for (int a = 0; a < m->nargs; a++) {
            printf("%s: ", m->prompts[a]);
            if (!fgets(in, sizeof(in), stdin)) return 0;
            trim_newline(in);
            if (!in[0] && a >= m->optional_from) break;     /* optional, left blank */
            for (char *c = in; *c; c++) if (*c == ' ' || *c == '\t') *c = '_';
            size_t used = strlen(line);
            snprintf(line + used, size - used, " %s", in);
        }
        return 1;
    }
}

int main(void) {
    srand((unsigned)time(NULL));
    printf("Loading registries...\n");
    if (!load_books(BOOKS_FILE) || !load_members(MEMBERS_FILE) || !load_copies(COPIES_FILE)) {
        printf("Startup aborted.\n"); return 1;
    }
    printf("Loaded %d book(s), %d member(s), %d copies.\n", g_book_count, g_member_count, g_copy_count);

    char model_choice[8];
    printf("Choose the token ledger model: 1=UTXO 2=Account: ");
    if (fgets(model_choice, sizeof(model_choice), stdin)) { if (model_choice[0]=='2') g_model = MODEL_ACCOUNT; }

    load_or_create_member_keys();
    init_accounts();
    for (int i = 0; i < g_member_count; i++) { g_member_nonce[i] = 0; g_member_fine[i] = 0; }

    chain_init(); pool_init();
    load_chain(); load_copy_state(); load_reservations(); load_pool();
    load_utxos(); load_accounts(); load_nonces_and_fines(); load_meta();

    if (g_chain.count > 0) {
        printf("Loaded existing chain with %d block(s). Validating before continuing...\n", g_chain.count);
        g_chain_was_valid_on_load = validate_chain(1);
        printf("Chain status: %s\n", g_chain_was_valid_on_load ? "VALID" : "INVALID — proceed with caution");
    } else {
        printf("Starting a fresh chain.\n");
    }
    print_menu();

    char line[512];
    int running = 1;
    while (running) {
        if (!read_menu_command(line, sizeof(line))) break;
        if (!line[0]) continue;
        char *cmd = strtok(line, " \t");
        if (!cmd) continue;

        if (!strcmp(cmd, "help")) print_help();
        else if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit")) { cmd_chain_save(); running = 0; }
        else if (!strcmp(cmd, "register_member")) {
            char *id=next_tok(), *name=next_tok(), *course=next_tok();
            if (id&&name&&course) cmd_register_member(id,name,course); else printf("usage: register_member <id> <name> <course>\n");
        }
        else if (!strcmp(cmd, "register_book")) {
            char *id=next_tok(), *title=next_tok(), *author=next_tok();
            if (id&&title&&author) cmd_register_book(id,title,author); else printf("usage: register_book <id> <title> <author>\n");
        }
        else if (!strcmp(cmd, "view_member")) { char *id=next_tok(); if (id) cmd_view_member(id); else printf("usage: view_member <id>\n"); }
        else if (!strcmp(cmd, "view_book")) { char *id=next_tok(); if (id) cmd_view_book(id); else printf("usage: view_book <id>\n"); }
        else if (!strcmp(cmd, "member_nonce")) { char *id=next_tok(); int idx=id?find_member_idx(id):-1; if (idx>=0) printf("Next expected nonce for %s: %lu\n", id, g_member_nonce[idx]); else printf("ERROR: Book or Member not found\n"); }
        else if (!strcmp(cmd, "add_copy")) {
            char *cid=next_tok(), *bid=next_tok(), *cond=next_tok();
            if (cid&&bid) cmd_add_copy(cid,bid,cond); else printf("usage: add_copy <copy_id> <book_id> [condition]\n");
        }
        else if (!strcmp(cmd, "view_copy")) { char *id=next_tok(); if (id) cmd_view_copy(id); else printf("usage: view_copy <copy_id>\n"); }
        else if (!strcmp(cmd, "mark_lost")) { char *cid=next_tok(), *reason=next_tok(); if (cid) cmd_mark_lost(cid,reason); else printf("usage: mark_lost <copy_id> <reason>\n"); }
        else if (!strcmp(cmd, "borrow_book")) { char *bid=next_tok(), *mid=next_tok(); if (bid&&mid) cmd_borrow_book(bid,mid); else printf("usage: borrow_book <book_id> <member_id>\n"); }
        else if (!strcmp(cmd, "return_book")) {
            char *cid=next_tok(), *mid=next_tok(), *cond=next_tok(), *reason=next_tok();
            if (cid&&mid) cmd_return_book(cid,mid,cond,reason); else printf("usage: return_book <copy_id> <member_id> [condition] [override_reason]\n");
        }
        else if (!strcmp(cmd, "renew_book")) { char *cid=next_tok(), *mid=next_tok(); if (cid&&mid) cmd_renew_book(cid,mid); else printf("usage: renew_book <copy_id> <member_id>\n"); }
        else if (!strcmp(cmd, "reserve_book")) { char *bid=next_tok(), *mid=next_tok(); if (bid&&mid) cmd_reserve_book(bid,mid); else printf("usage: reserve_book <book_id> <member_id>\n"); }
        else if (!strcmp(cmd, "reservation_status")) { char *bid=next_tok(); if (bid) cmd_reservation_status(bid); else printf("usage: reservation_status <book_id>\n"); }
        else if (!strcmp(cmd, "check_overdue")) cmd_check_overdue();
        else if (!strcmp(cmd, "view_fines")) cmd_view_fines();
        else if (!strcmp(cmd, "settle_fine")) { char *mid=next_tok(), *amt=next_tok(); if (mid&&amt) cmd_settle_fine(mid, atoi(amt)); else printf("usage: settle_fine <member_id> <amount>\n"); }
        else if (!strcmp(cmd, "token_transfer") || !strcmp(cmd, "account_transfer")) {
            char *from=next_tok(), *to=next_tok(), *amt=next_tok();
            if (from&&to&&amt) { if (g_model==MODEL_UTXO) utxo_transfer(from,to,atoi(amt)); else account_transfer(from,to,atoi(amt)); }
            else printf("usage: token_transfer <from> <to> <amount>\n");
        }
        else if (!strcmp(cmd, "token_balance")) { char *id=next_tok(); if (id) printf("Balance for %s: %d\n", id, g_model==MODEL_UTXO?utxo_balance(id):(find_account(id)?find_account(id)->balance:0)); else printf("usage: token_balance <member_id>\n"); }
        else if (!strcmp(cmd, "utxo_view")) { if (g_model==MODEL_UTXO) print_utxo_set(); else printf("Switch to the UTXO model at startup to use this.\n"); }
        else if (!strcmp(cmd, "account_balance")) { char *id=next_tok(); if (id) { Account *a=find_account(id); printf("Balance for %s: %d\n", id, a?a->balance:0);} else print_accounts(); }
        else if (!strcmp(cmd, "account_nonce")) { char *id=next_tok(); int idx=id?find_member_idx(id):-1; if (idx>=0) printf("Next expected nonce for %s: %lu\n", id, g_member_nonce[idx]); else printf("ERROR: Book or Member not found\n"); }
        else if (!strcmp(cmd, "transaction_history")) { char *id=next_tok(); if (id) print_tx_history(id); else printf("usage: transaction_history <member_id>\n"); }
        else if (!strcmp(cmd, "pool_view")) cmd_pool_view();
        else if (!strcmp(cmd, "mine_solo")) cmd_mine_solo();
        else if (!strcmp(cmd, "mine_pool")) { char *n=next_tok(); cmd_mine_pool(n?atoi(n):4); }
        else if (!strcmp(cmd, "mine_cloud")) { char *r=next_tok(); if (r) cmd_mine_cloud(atoi(r)); else printf("usage: mine_cloud <rounds>\n"); }
        else if (!strcmp(cmd, "chain_view")) cmd_chain_view();
        else if (!strcmp(cmd, "validate_chain")) { int ok=validate_chain(1); printf("\nOverall: %s\n", ok?"VALID":"TAMPERED/CORRUPT"); }
        else if (!strcmp(cmd, "chain_save")) cmd_chain_save();
        else if (!strcmp(cmd, "chain_load")) cmd_chain_load();
        else if (!strcmp(cmd, "difficulty_status")) printf("Current difficulty: %d (hash must start with %d leading zero hex chars)\n", g_difficulty, g_difficulty);
        else if (!strcmp(cmd, "set_difficulty")) { char *d=next_tok(); if (d) { g_difficulty=atoi(d); if(g_difficulty<1)g_difficulty=1; if(g_difficulty>4)g_difficulty=4; printf("Difficulty set to %d.\n", g_difficulty);} else printf("usage: set_difficulty <1-4>\n"); }
        else if (!strcmp(cmd, "fraud_review")) cmd_fraud_review();
        else if (!strcmp(cmd, "approve_suspicious")) { char *id=next_tok(); int i=id?atoi(id):-1; if (i>=0&&i<g_pool.count) { snprintf(g_pool.items[i].status,sizeof(g_pool.items[i].status),"PENDING"); printf("OK: item %d approved, now PENDING.\n", i);} else printf("usage: approve_suspicious <pool_index>\n"); }
        else if (!strcmp(cmd, "reject_suspicious")) { char *id=next_tok(); int i=id?atoi(id):-1; if (i>=0&&i<g_pool.count) { pool_remove_at(i); printf("OK: item %d rejected and removed.\n", i);} else printf("usage: reject_suspicious <pool_index>\n"); }
        else if (!strcmp(cmd, "lending_history")) { char *id=next_tok(); cmd_lending_history(id, NULL); }
        else if (!strcmp(cmd, "member_history")) { char *id=next_tok(); if (id) cmd_lending_history(id, NULL); else printf("usage: member_history <member_id>\n"); }
        else if (!strcmp(cmd, "book_history")) { char *id=next_tok(); if (id) cmd_lending_history(NULL, id); else printf("usage: book_history <book_id>\n"); }
        else if (!strcmp(cmd, "tamper_demo")) { char *b=next_tok(); if (b) cmd_tamper_demo(atoi(b)); else printf("usage: tamper_demo <block_index>\n"); }
        else if (!strcmp(cmd, "simulate_replay")) { char *id=next_tok(); if (id) cmd_simulate_replay(id); else printf("usage: simulate_replay <member_id>\n"); }
        else printf("Unknown command. Type 'help'.\n");
    }

    free(g_chain.items); free(g_pool.items);
    printf("Goodbye.\n");
    return 0;
}
