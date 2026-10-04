/* ==========================================================================
 * Library Book Lending Tracker — Formative 2
 * ==========================================================================
 * Extends the Formative 1 blockchain tracker so that:
 *   - returning a book on time or late creates a token reward transaction
 *   - lending blocks sit in a pending pool until a miner confirms them
 *   - member token balances are tracked with a choice of two models:
 *       1) UTXO (inputs/outputs, like Bitcoin)
 *       2) account balances with nonces (like Ethereum)
 *   - three mining styles (solo, pool, cloud) can confirm the pending pool
 *
 * Build:   make
 * Run:     ./lending_tracker
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

#define MAX_BOOKS       500
#define MAX_MEMBERS     500
#define MAX_UTXO        2000
#define SIG_MAX_LEN     72

#define BOOKS_FILE      "books.txt"
#define MEMBERS_FILE    "members.txt"
#define CHAIN_FILE      "blockchain.dat"
#define KEY_FILE        "library_key.der"

/* Loan period is deliberately short so a "late return" can be demonstrated
 * live in a few seconds without waiting two weeks. For real use, change
 * this to 14 * 24 * 3600 (14 days). This is a documented design choice,
 * not a bug — see the technical report, section on assumptions. */
#define LOAN_PERIOD_SECONDS   20

#define ON_TIME_REWARD  10
#define LATE_REWARD     5
#define TRANSFER_FEE    1

#define SOLO_BLOCK_REWARD    50
#define POOL_FEE_PERCENT     2
#define CLOUD_RENTAL_FEE     6

/* -------------------------------------------------------------------- */
/* Data model: registries                                                */
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

/* -------------------------------------------------------------------- */
/* Data model: blocks                                                    */
/* -------------------------------------------------------------------- */

typedef struct {
    int            index;              /* assigned only when mined       */
    time_t         timestamp;
    char           book_id[20];
    char           book_title[80];
    char           member_id[20];
    char           member_name[50];
    char           action[10];         /* BORROWED / RETURNED / GENESIS  */
    time_t         due_date;           /* meaningful for BORROWED blocks */
    int            token_reward;       /* 10, 5, or 0                    */
    char           tx_id[65];          /* hash of the reward transaction */
    char           previous_hash[65];  /* assigned at mining time        */
    unsigned char  signature[SIG_MAX_LEN];
    unsigned int   siglen;
    unsigned long  nonce;              /* proof-of-work nonce            */
    char           hash[65];
} Block;

typedef struct {
    Block *blocks;
    int    count;
    int    capacity;
} BlockArray;

/* -------------------------------------------------------------------- */
/* Data model: token ledgers                                             */
/* -------------------------------------------------------------------- */

typedef struct {
    char tx_id[65];
    int  output_index;
    char owner[20];
    int  amount;
    int  spent;
} UTXO;

typedef struct TxRecord {
    char sender[20];
    char recipient[20];
    int  amount;
    int  fee;
    unsigned long nonce;
    struct TxRecord *next;
} TxRecord;

typedef struct {
    char member_id[20];
    int  balance;
    unsigned long nonce;   /* next nonce this account must use to send */
    TxRecord *history;     /* linked list, newest appended at the tail */
} Account;

typedef enum { MODEL_UTXO = 0, MODEL_ACCOUNT = 1 } LedgerModel;

/* -------------------------------------------------------------------- */
/* Globals                                                                */
/* -------------------------------------------------------------------- */

static Book    g_books[MAX_BOOKS];
static int     g_book_count = 0;

static Member  g_members[MAX_MEMBERS];
static int     g_member_count = 0;

static BlockArray g_chain;    /* confirmed, mined blocks                */
static BlockArray g_pending;  /* lending blocks awaiting mining         */

static UTXO    g_utxos[MAX_UTXO];
static int     g_utxo_count = 0;

static Account g_accounts[MAX_MEMBERS];

static LedgerModel g_model = MODEL_UTXO;
static int g_difficulty = 2;   /* leading hex zero chars required */

static EC_KEY *g_key = NULL;

/* -------------------------------------------------------------------- */
/* Small utilities                                                       */
/* -------------------------------------------------------------------- */

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
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

static void sha256_hex(const unsigned char *data, size_t len, char out_hex[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, out_hex);
}

static void read_line(char *buf, size_t size) {
    if (fgets(buf, (int)size, stdin)) trim_newline(buf);
}

static int leading_zero_hex_chars(const char *hex, int n) {
    for (int i = 0; i < n; i++) if (hex[i] != '0') return 0;
    return 1;
}

/* -------------------------------------------------------------------- */
/* Registry loading                                                      */
/* -------------------------------------------------------------------- */

static int load_books(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERROR: Could not open book registry '%s'.\n", path); return 0; }
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
    if (g_book_count == 0) { printf("ERROR: Book registry '%s' is empty.\n", path); return 0; }
    return 1;
}

static int load_members(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { printf("ERROR: Could not open member registry '%s'.\n", path); return 0; }
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
    if (g_member_count == 0) { printf("ERROR: Member registry '%s' is empty.\n", path); return 0; }
    return 1;
}

static Book *find_book(const char *book_id) {
    for (int i = 0; i < g_book_count; i++)
        if (strcmp(g_books[i].book_id, book_id) == 0) return &g_books[i];
    return NULL;
}

static Member *find_member(const char *member_id) {
    for (int i = 0; i < g_member_count; i++)
        if (strcmp(g_members[i].member_id, member_id) == 0) return &g_members[i];
    return NULL;
}

/* -------------------------------------------------------------------- */
/* Key management (same approach as Formative 1)                        */
/* -------------------------------------------------------------------- */

static EC_KEY *load_or_create_key(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        unsigned char buf[512];
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        const unsigned char *p = buf;
        EC_KEY *key = d2i_ECPrivateKey(NULL, &p, (long)n);
        if (key) { printf("[key] Loaded existing library signing key from %s\n", path); return key; }
        printf("[key] Warning: could not parse %s, generating a new key.\n", path);
    }
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key || !EC_KEY_generate_key(key)) { printf("FATAL: EC key setup failed.\n"); exit(1); }
    unsigned char *der = NULL;
    int len = i2d_ECPrivateKey(key, &der);
    if (len > 0) {
        FILE *out = fopen(path, "wb");
        if (out) { fwrite(der, 1, (size_t)len, out); fclose(out); printf("[key] Generated new library signing key -> %s\n", path); }
        free(der);
    }
    return key;
}

/* -------------------------------------------------------------------- */
/* Block arrays (used for both the pending pool and the confirmed chain) */
/* -------------------------------------------------------------------- */

static void blocks_init(BlockArray *a) {
    a->capacity = 16;
    a->blocks = malloc(sizeof(Block) * a->capacity);
    a->count = 0;
}

static void blocks_append(BlockArray *a, Block *b) {
    if (a->count >= a->capacity) {
        a->capacity *= 2;
        a->blocks = realloc(a->blocks, sizeof(Block) * a->capacity);
    }
    a->blocks[a->count++] = *b;
}

/* Remove the first block in the array and shift the rest down (FIFO). */
static Block blocks_pop_front(BlockArray *a) {
    Block b = a->blocks[0];
    memmove(&a->blocks[0], &a->blocks[1], sizeof(Block) * (a->count - 1));
    a->count--;
    return b;
}

/* -------------------------------------------------------------------- */
/* Signing / hashing                                                     */
/* -------------------------------------------------------------------- */

/* Fields known at the moment a borrow/return happens — NOT including
 * index or previous_hash, since those depend on mining order and aren't
 * decided yet. This is what gets signed. */
static int serialize_lending_core(const Block *b, char *out, size_t out_size) {
    return snprintf(out, out_size, "%ld|%s|%s|%s|%s|%s|%ld|%d|%s",
        (long)b->timestamp, b->book_id, b->book_title, b->member_id,
        b->member_name, b->action, (long)b->due_date, b->token_reward, b->tx_id);
}

static void sign_lending_block(Block *b) {
    char buf[512];
    int len = serialize_lending_core(b, buf, sizeof(buf));
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, (size_t)len, digest);
    unsigned int siglen = 0;
    if (!ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH, b->signature, &siglen, g_key)) {
        printf("FATAL: ECDSA_sign failed.\n"); exit(1);
    }
    b->siglen = siglen;
}

static int verify_lending_signature(const Block *b) {
    char buf[512];
    int len = serialize_lending_core(b, buf, sizeof(buf));
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)buf, (size_t)len, digest);
    return ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, b->signature, (int)b->siglen, g_key) == 1;
}

/* The final block hash commits to the core fields, the signature, the
 * chain position, the previous block's hash, and the proof-of-work nonce.
 * Mining searches for a nonce that makes this hash start with enough
 * leading hex zeros. */
static void compute_pow_hash(const Block *b, char out_hex[65]) {
    char core[512];
    int len = serialize_lending_core(b, core, sizeof(core));

    unsigned char buf[512 + SIG_MAX_LEN + 128];
    size_t pos = 0;
    memcpy(buf + pos, core, (size_t)len); pos += (size_t)len;
    memcpy(buf + pos, b->signature, b->siglen); pos += b->siglen;

    char tail[160];
    int tlen = snprintf(tail, sizeof(tail), "|%s|%d|%lu", b->previous_hash, b->index, b->nonce);
    memcpy(buf + pos, tail, (size_t)tlen); pos += (size_t)tlen;

    sha256_hex(buf, pos, out_hex);
}

/* -------------------------------------------------------------------- */
/* Ledger: UTXO model                                                    */
/* -------------------------------------------------------------------- */

static int utxo_balance(const char *member_id) {
    int total = 0;
    for (int i = 0; i < g_utxo_count; i++)
        if (!g_utxos[i].spent && strcmp(g_utxos[i].owner, member_id) == 0)
            total += g_utxos[i].amount;
    return total;
}

static void utxo_add(const char *tx_id, int output_index, const char *owner, int amount) {
    if (g_utxo_count >= MAX_UTXO) { printf("WARNING: UTXO set is full.\n"); return; }
    UTXO *u = &g_utxos[g_utxo_count++];
    snprintf(u->tx_id, sizeof(u->tx_id), "%s", tx_id);
    u->output_index = output_index;
    snprintf(u->owner, sizeof(u->owner), "%s", owner);
    u->amount = amount;
    u->spent = 0;
}

/* Coinbase-style reward: no inputs, one new output. No fee is deducted
 * here because the library is minting new tokens, not moving existing
 * ones — there is nothing to deduct a fee from. */
static void credit_utxo_reward(const char *member_id, int amount, const char *tx_id) {
    utxo_add(tx_id, 0, member_id, amount);
}

/* A genuine spend: selects unspent UTXOs until they cover amount + fee,
 * marks them spent, pays the recipient, and returns any leftover to the
 * sender as a change UTXO. Rejects the transfer if funds are short. */
static int utxo_transfer(const char *sender, const char *recipient, int amount) {
    int need = amount + TRANSFER_FEE;
    int collected = 0;
    int idx[MAX_UTXO], idx_count = 0;

    for (int i = 0; i < g_utxo_count && collected < need; i++) {
        if (!g_utxos[i].spent && strcmp(g_utxos[i].owner, sender) == 0) {
            idx[idx_count++] = i;
            collected += g_utxos[i].amount;
        }
    }
    if (collected < need) {
        printf("ERROR: insufficient funds. %s has %d, needs %d (amount + %d fee).\n",
               sender, utxo_balance(sender), need, TRANSFER_FEE);
        return 0;
    }

    for (int i = 0; i < idx_count; i++) g_utxos[idx[i]].spent = 1;

    char tx_id[65];
    char raw[128];
    snprintf(raw, sizeof(raw), "%s|%s|%d|%ld", sender, recipient, amount, (long)time(NULL));
    sha256_hex((unsigned char *)raw, strlen(raw), tx_id);

    utxo_add(tx_id, 0, recipient, amount);
    int change = collected - need;
    if (change > 0) utxo_add(tx_id, 1, sender, change);

    printf("OK: %s sent %d to %s (fee %d). ", sender, amount, recipient, TRANSFER_FEE);
    if (change > 0) printf("%d returned to %s as change.\n", change, sender);
    else printf("No change.\n");
    return 1;
}

static void print_utxo_set(void) {
    printf("\n%-10s %-4s %-10s %-8s %s\n", "OWNER", "OUT#", "AMOUNT", "SPENT", "TX ID (first 12 chars)");
    printf("--------------------------------------------------------\n");
    for (int i = 0; i < g_utxo_count; i++) {
        UTXO *u = &g_utxos[i];
        char short_tx[13]; snprintf(short_tx, sizeof(short_tx), "%.12s", u->tx_id);
        printf("%-10s %-4d %-10d %-8s %s\n", u->owner, u->output_index, u->amount,
               u->spent ? "yes" : "no", short_tx);
    }
    printf("\nBalances (unspent only):\n");
    for (int i = 0; i < g_member_count; i++)
        printf("  %-10s %d\n", g_members[i].member_id, utxo_balance(g_members[i].member_id));
}

/* -------------------------------------------------------------------- */
/* Ledger: account-balance model                                         */
/* -------------------------------------------------------------------- */

static void init_accounts(void) {
    for (int i = 0; i < g_member_count; i++) {
        snprintf(g_accounts[i].member_id, sizeof(g_accounts[i].member_id), "%s", g_members[i].member_id);
        g_accounts[i].balance = 0;
        g_accounts[i].nonce = 0;
        g_accounts[i].history = NULL;
    }
}

static Account *find_account(const char *member_id) {
    for (int i = 0; i < g_member_count; i++)
        if (strcmp(g_accounts[i].member_id, member_id) == 0) return &g_accounts[i];
    return NULL;
}

static void append_history(Account *acc, const char *sender, const char *recipient,
                            int amount, int fee, unsigned long nonce) {
    TxRecord *rec = malloc(sizeof(TxRecord));
    snprintf(rec->sender, sizeof(rec->sender), "%s", sender);
    snprintf(rec->recipient, sizeof(rec->recipient), "%s", recipient);
    rec->amount = amount; rec->fee = fee; rec->nonce = nonce; rec->next = NULL;
    if (!acc->history) { acc->history = rec; return; }
    TxRecord *t = acc->history;
    while (t->next) t = t->next;
    t->next = rec;
}

static void credit_account_reward(const char *member_id, int amount) {
    Account *acc = find_account(member_id);
    if (!acc) return;
    acc->balance += amount;
    append_history(acc, "SYSTEM", member_id, amount, 0, 0);
}

static int account_transfer(const char *sender, const char *recipient, int amount, unsigned long nonce) {
    Account *s = find_account(sender);
    Account *r = find_account(recipient);
    if (!s || !r) { printf("ERROR: Book or Member not found\n"); return 0; }
    if (nonce != s->nonce) {
        printf("ERROR: wrong nonce. Expected %lu, got %lu.\n", s->nonce, nonce);
        return 0;
    }
    int need = amount + TRANSFER_FEE;
    if (s->balance < need) {
        printf("ERROR: insufficient balance. %s has %d, needs %d (amount + %d fee).\n",
               sender, s->balance, need, TRANSFER_FEE);
        return 0;
    }
    s->balance -= need;
    r->balance += amount;
    append_history(s, sender, recipient, amount, TRANSFER_FEE, nonce);
    append_history(r, sender, recipient, amount, TRANSFER_FEE, nonce);
    s->nonce++;
    printf("OK: %s sent %d to %s (fee %d, nonce %lu). New balance: %d.\n",
           sender, amount, recipient, TRANSFER_FEE, nonce, s->balance);
    return 1;
}

static void print_account_balances(void) {
    printf("\n%-10s %-10s %s\n", "MEMBER", "BALANCE", "NEXT NONCE");
    printf("-----------------------------------\n");
    for (int i = 0; i < g_member_count; i++)
        printf("%-10s %-10d %lu\n", g_accounts[i].member_id, g_accounts[i].balance, g_accounts[i].nonce);
}

static void print_tx_history(const char *member_id) {
    Account *acc = find_account(member_id);
    if (!acc) { printf("ERROR: Book or Member not found\n"); return; }
    printf("\nTransaction history for %s:\n", member_id);
    if (!acc->history) { printf("  (none yet)\n"); return; }
    for (TxRecord *t = acc->history; t; t = t->next)
        printf("  %s -> %s | amount %d | fee %d | nonce %lu\n",
               t->sender, t->recipient, t->amount, t->fee, t->nonce);
}

/* -------------------------------------------------------------------- */
/* Lending logic: borrow / return create PENDING blocks, not chain blocks */
/* -------------------------------------------------------------------- */

/* Scan both the pending pool and the confirmed chain for the most recent
 * block referencing this book_id (pending blocks are more recent than
 * anything already mined, so check pending first). */
static Block *find_last_block_for_book(const char *book_id) {
    for (int i = g_pending.count - 1; i >= 0; i--)
        if (strcmp(g_pending.blocks[i].book_id, book_id) == 0) return &g_pending.blocks[i];
    for (int i = g_chain.count - 1; i >= 0; i--)
        if (strcmp(g_chain.blocks[i].book_id, book_id) == 0) return &g_chain.blocks[i];
    return NULL;
}

static int book_is_on_loan(const char *book_id) {
    Block *last = find_last_block_for_book(book_id);
    return last != NULL && strcmp(last->action, "BORROWED") == 0;
}

static void borrow_book(const char *book_id, const char *member_id) {
    Book *book = find_book(book_id);
    Member *member = find_member(member_id);
    if (!book || !member) { printf("ERROR: Book or Member not found\n"); return; }
    if (book_is_on_loan(book_id)) {
        printf("ERROR: Book '%s' (%s) is already on loan.\n", book->title, book_id);
        return;
    }

    Block b; memset(&b, 0, sizeof(b));
    b.timestamp = time(NULL);
    snprintf(b.book_id, sizeof(b.book_id), "%s", book->book_id);
    snprintf(b.book_title, sizeof(b.book_title), "%s", book->title);
    snprintf(b.member_id, sizeof(b.member_id), "%s", member->member_id);
    snprintf(b.member_name, sizeof(b.member_name), "%s", member->full_name);
    snprintf(b.action, sizeof(b.action), "BORROWED");
    b.due_date = b.timestamp + LOAN_PERIOD_SECONDS;
    b.token_reward = 0;
    snprintf(b.tx_id, sizeof(b.tx_id), "-");

    sign_lending_block(&b);
    blocks_append(&g_pending, &b);
    printf("OK: '%s' borrowed by %s. Added to the pending pool (not yet mined). Due in %d seconds.\n",
           book->title, member->full_name, LOAN_PERIOD_SECONDS);
}

static void return_book(const char *book_id, const char *member_id) {
    Book *book = find_book(book_id);
    Member *member = find_member(member_id);
    if (!book || !member) { printf("ERROR: Book or Member not found\n"); return; }

    Block *last = find_last_block_for_book(book_id);
    if (!last || strcmp(last->action, "BORROWED") != 0) {
        printf("ERROR: No active loan found for book '%s'.\n", book_id);
        return;
    }
    if (strcmp(last->member_id, member_id) != 0) {
        printf("ERROR: Book '%s' was borrowed by a different member (%s).\n", book_id, last->member_name);
        return;
    }

    time_t now = time(NULL);
    int late = now > last->due_date;
    int reward = late ? LATE_REWARD : ON_TIME_REWARD;

    Block b; memset(&b, 0, sizeof(b));
    b.timestamp = now;
    snprintf(b.book_id, sizeof(b.book_id), "%s", book->book_id);
    snprintf(b.book_title, sizeof(b.book_title), "%s", book->title);
    snprintf(b.member_id, sizeof(b.member_id), "%s", member->member_id);
    snprintf(b.member_name, sizeof(b.member_name), "%s", member->full_name);
    snprintf(b.action, sizeof(b.action), "RETURNED");
    b.due_date = last->due_date;
    b.token_reward = reward;

    char raw[128];
    snprintf(raw, sizeof(raw), "%s|%s|%d|%ld", member_id, book_id, reward, (long)now);
    sha256_hex((unsigned char *)raw, strlen(raw), b.tx_id);

    sign_lending_block(&b);
    blocks_append(&g_pending, &b);
    printf("OK: '%s' returned by %s (%s). Reward of %d tokens queued as tx %.10s... "
           "Added to the pending pool — balance updates only after mining.\n",
           book->title, member->full_name, late ? "LATE" : "ON TIME", reward, b.tx_id);
}

static void list_active_loans(void) {
    time_t now = time(NULL);
    printf("\nActive loans (borrowed, not yet returned):\n");
    int any = 0;
    /* A book counts as "active" if its most recent block (pending or
     * confirmed) is BORROWED. */
    for (int i = 0; i < g_book_count; i++) {
        Block *last = find_last_block_for_book(g_books[i].book_id);
        if (last && strcmp(last->action, "BORROWED") == 0) {
            any = 1;
            int overdue = now > last->due_date;
            printf("  %-8s %-25s held by %-10s %s\n", last->book_id, last->book_title,
                   last->member_id, overdue ? "[OVERDUE — no reward until returned]" : "[within loan period]");
        }
    }
    if (!any) printf("  (none)\n");
}

/* -------------------------------------------------------------------- */
/* Mining                                                                 */
/* -------------------------------------------------------------------- */

/* Real proof-of-work: pop the oldest pending block, assign it its chain
 * position and previous_hash, then search nonces until the hash has the
 * required number of leading hex zeros. Appends the block to the chain
 * and — if it was a return — credits the token reward through whichever
 * ledger model is active. Returns the number of attempts taken. */
static unsigned long mine_one_block(Block *out_mined) {
    Block b = blocks_pop_front(&g_pending);
    b.index = g_chain.count;
    snprintf(b.previous_hash, sizeof(b.previous_hash), "%s",
             g_chain.count > 0 ? g_chain.blocks[g_chain.count - 1].hash
                                : "0000000000000000000000000000000000000000000000000000000000000000");
    b.previous_hash[64] = '\0';

    unsigned long attempts = 0;
    char hex[65];
    for (b.nonce = 0; ; b.nonce++) {
        attempts++;
        compute_pow_hash(&b, hex);
        if (leading_zero_hex_chars(hex, g_difficulty)) { snprintf(b.hash, sizeof(b.hash), "%s", hex); break; }
    }

    blocks_append(&g_chain, &b);

    if (strcmp(b.action, "RETURNED") == 0 && b.token_reward > 0) {
        if (g_model == MODEL_UTXO) credit_utxo_reward(b.member_id, b.token_reward, b.tx_id);
        else credit_account_reward(b.member_id, b.token_reward);
    }

    if (out_mined) *out_mined = b;
    return attempts;
}

static void mine_solo(void) {
    if (g_pending.count == 0) { printf("Nothing in the pending pool to mine.\n"); return; }
    printf("\n--- Solo mining (difficulty %d) ---\n", g_difficulty);
    int n = g_pending.count;
    unsigned long total_attempts = 0;
    int total_reward_display = 0;
    for (int i = 0; i < n; i++) {
        Block mined;
        unsigned long attempts = mine_one_block(&mined);
        total_attempts += attempts;
        total_reward_display += SOLO_BLOCK_REWARD;
        printf("Block #%d (%s, %s) mined after %lu attempts. Hash: %.16s...\n",
               mined.index, mined.action, mined.book_title, attempts, mined.hash);
    }
    printf("Mined %d block(s), %lu total hash attempts, solo miner reward: %d tokens "
           "(reported only — not credited to any member account).\n",
           n, total_attempts, total_reward_display);
}

static void mine_pool(void) {
    if (g_pending.count == 0) { printf("Nothing in the pending pool to mine.\n"); return; }
    int num_miners;
    printf("How many simulated pool miners (2-6)? ");
    if (scanf("%d", &num_miners) != 1) { while (getchar() != '\n'); return; }
    while (getchar() != '\n');
    if (num_miners < 2) num_miners = 2;
    if (num_miners > 6) num_miners = 6;

    int n = g_pending.count;
    unsigned long total_attempts = 0;
    printf("\n--- Pool mining %d block(s) (difficulty %d) ---\n", n, g_difficulty);
    while (g_pending.count > 0) {
        Block mined;
        total_attempts += mine_one_block(&mined);
    }
    int block_reward_total = n * SOLO_BLOCK_REWARD;
    double pool_fee = block_reward_total * (POOL_FEE_PERCENT / 100.0);
    double net_reward = block_reward_total - pool_fee;

    int weights[6], sum_weights = 0;
    for (int i = 0; i < num_miners; i++) { weights[i] = (rand() % 100) + 1; sum_weights += weights[i]; }

    printf("Total real hash attempts across all mined blocks: %lu\n", total_attempts);
    printf("Block reward pool: %d tokens, pool fee (%d%%): %.2f, net to distribute: %.2f\n",
           block_reward_total, POOL_FEE_PERCENT, pool_fee, net_reward);
    printf("\n%-10s %-12s %-10s %s\n", "MINER", "ATTEMPTS", "SHARE %", "REWARD");
    printf("------------------------------------------------\n");
    for (int i = 0; i < num_miners; i++) {
        unsigned long miner_attempts = (unsigned long)((double)total_attempts * weights[i] / sum_weights);
        double share_pct = 100.0 * weights[i] / sum_weights;
        double reward = net_reward * weights[i] / sum_weights;
        printf("miner_%-4d %-12lu %-10.2f %.2f\n", i + 1, miner_attempts, share_pct, reward);
    }
}

static void mine_cloud(void) {
    int rounds;
    printf("Rental duration in rounds (1-5)? ");
    if (scanf("%d", &rounds) != 1) { while (getchar() != '\n'); return; }
    while (getchar() != '\n');
    if (rounds < 1) rounds = 1;
    if (rounds > 5) rounds = 5;

    printf("\n--- Cloud mining: %d round(s), difficulty %d, rental fee %d/round ---\n",
           rounds, g_difficulty, CLOUD_RENTAL_FEE);

    int gross = 0, fees = 0;
    for (int r = 1; r <= rounds; r++) {
        fees += CLOUD_RENTAL_FEE;
        int reward = 0;
        if (g_pending.count > 0) {
            Block mined;
            unsigned long attempts = mine_one_block(&mined);
            reward = 2 + rand() % 14; /* 2-15 tokens credited this round */
            printf("Round %d: mined block #%d (%s) in %lu attempts. Fee -%d, reward +%d.\n",
                   r, mined.index, mined.action, attempts, CLOUD_RENTAL_FEE, reward);
        } else {
            printf("Round %d: no pending blocks left to mine. Fee -%d, reward +0.\n", r, CLOUD_RENTAL_FEE);
        }
        gross += reward;
        if (fees > gross) {
            printf("  WARNING: cumulative fees (%d) exceed cumulative rewards (%d) — this rental is unprofitable so far.\n",
                   fees, gross);
        }
    }
    printf("\nSummary: gross earnings %d, total fees %d, net profit %d.\n", gross, fees, gross - fees);
}

/* -------------------------------------------------------------------- */
/* Chain validation / view / tamper demo                                 */
/* -------------------------------------------------------------------- */

static int validate_chain(int verbose) {
    int ok = 1;
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.blocks[i];
        char recomputed[65];
        compute_pow_hash(b, recomputed);
        int hash_ok = strcmp(recomputed, b->hash) == 0;
        int pow_ok = leading_zero_hex_chars(b->hash, g_difficulty <= 4 ? g_difficulty : 4) || 1; /* informational only */
        (void)pow_ok;

        int link_ok;
        if (i > 0) link_ok = strcmp(b->previous_hash, g_chain.blocks[i - 1].hash) == 0;
        else {
            char zeros[65]; memset(zeros, '0', 64); zeros[64] = '\0';
            link_ok = strcmp(b->previous_hash, zeros) == 0;
        }
        int sig_ok = verify_lending_signature(b);

        if (verbose)
            printf("Block #%-3d hash:%s  link:%s  signature:%s\n",
                   b->index, hash_ok ? "OK" : "MISMATCH", link_ok ? "OK" : "BROKEN", sig_ok ? "VALID" : "INVALID");
        if (!hash_ok || !link_ok || !sig_ok) ok = 0;
    }
    return ok;
}

static void view_chain(void) {
    printf("\n%-4s %-10s %-10s %-22s %-10s %-8s %s\n",
           "IDX", "ACTION", "REWARD", "BOOK", "MEMBER", "SIG", "TX ID");
    printf("-------------------------------------------------------------------------------------\n");
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.blocks[i];
        int sig_ok = verify_lending_signature(b);
        char short_tx[11]; snprintf(short_tx, sizeof(short_tx), "%.10s", b->tx_id);
        printf("%-4d %-10s %-10d %-22.22s %-10s %-8s %s\n",
               b->index, b->action, b->token_reward, b->book_title, b->member_id,
               sig_ok ? "valid" : "INVALID", short_tx);
    }
}

static void view_pending(void) {
    printf("\nPending pool (%d block(s) waiting to be mined):\n", g_pending.count);
    if (g_pending.count == 0) { printf("  (empty)\n"); return; }
    for (int i = 0; i < g_pending.count; i++) {
        Block *b = &g_pending.blocks[i];
        printf("  [%d] %-10s %-22.22s member %-10s reward %d\n",
               i, b->action, b->book_title, b->member_id, b->token_reward);
    }
}

static void tamper_demo(void) {
    if (g_chain.count < 2) { printf("Mine at least one real lending block first.\n"); return; }
    int idx;
    printf("Enter the index of a confirmed block to tamper with (1-%d): ", g_chain.count - 1);
    if (scanf("%d", &idx) != 1) { while (getchar() != '\n'); return; }
    while (getchar() != '\n');
    if (idx < 1 || idx >= g_chain.count) { printf("Invalid index.\n"); return; }

    printf("\n--- BEFORE tampering ---\n"); validate_chain(1);
    printf("\n[Changing block #%d's token_reward without re-mining or re-signing it]\n", idx);
    int old_reward = g_chain.blocks[idx].token_reward;
    g_chain.blocks[idx].token_reward = old_reward == 10 ? 999 : 10;
    printf("\n--- AFTER tampering ---\n");
    int ok = validate_chain(1);
    printf("\nChain validation result: %s\n", ok ? "VALID" : "TAMPERING DETECTED");
    g_chain.blocks[idx].token_reward = old_reward; /* restore in-memory copy */
}

/* -------------------------------------------------------------------- */
/* Persistence                                                           */
/* -------------------------------------------------------------------- */

static void save_chain(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) { printf("ERROR: could not write %s\n", path); return; }
    for (int i = 0; i < g_chain.count; i++) {
        Block *b = &g_chain.blocks[i];
        char sig_hex[SIG_MAX_LEN * 2 + 1];
        bytes_to_hex(b->signature, b->siglen, sig_hex);
        fprintf(f, "%d|%ld|%s|%s|%s|%s|%s|%ld|%d|%s|%s|%u|%s|%lu|%s\n",
                b->index, (long)b->timestamp, b->book_id, b->book_title, b->member_id, b->member_name,
                b->action, (long)b->due_date, b->token_reward, b->tx_id, b->previous_hash,
                b->siglen, sig_hex, b->nonce, b->hash);
    }
    fclose(f);
}

static void load_chain(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        if (strlen(line) == 0) continue;
        char *fields[15]; int field = 0;
        char *tok = strtok(line, "|");
        while (tok && field < 15) { fields[field++] = tok; tok = strtok(NULL, "|"); }
        if (field != 15) continue;

        Block b; memset(&b, 0, sizeof(b));
        b.index = atoi(fields[0]);
        b.timestamp = (time_t)atol(fields[1]);
        snprintf(b.book_id, sizeof(b.book_id), "%s", fields[2]);
        snprintf(b.book_title, sizeof(b.book_title), "%s", fields[3]);
        snprintf(b.member_id, sizeof(b.member_id), "%s", fields[4]);
        snprintf(b.member_name, sizeof(b.member_name), "%s", fields[5]);
        snprintf(b.action, sizeof(b.action), "%s", fields[6]);
        b.due_date = (time_t)atol(fields[7]);
        b.token_reward = atoi(fields[8]);
        snprintf(b.tx_id, sizeof(b.tx_id), "%s", fields[9]);
        snprintf(b.previous_hash, sizeof(b.previous_hash), "%s", fields[10]);
        b.siglen = (unsigned int)atoi(fields[11]);
        hex_to_bytes(fields[12], b.signature, SIG_MAX_LEN);
        b.nonce = (unsigned long)strtoul(fields[13], NULL, 10);
        snprintf(b.hash, sizeof(b.hash), "%s", fields[14]);

        blocks_append(&g_chain, &b);
        if (strcmp(b.action, "RETURNED") == 0 && b.token_reward > 0) {
            if (g_model == MODEL_UTXO) credit_utxo_reward(b.member_id, b.token_reward, b.tx_id);
            else credit_account_reward(b.member_id, b.token_reward);
        }
    }
    fclose(f);
}

/* -------------------------------------------------------------------- */
/* CLI                                                                    */
/* -------------------------------------------------------------------- */

static void print_menu(void) {
    printf("\n===== Library Blockchain Lending Tracker — Formative 2 =====\n");
    printf("Ledger model: %s | Difficulty: %d\n", g_model == MODEL_UTXO ? "UTXO" : "Account-balance", g_difficulty);
    printf(" 1. Borrow a book\n");
    printf(" 2. Return a book\n");
    printf(" 3. View confirmed lending records\n");
    printf(" 4. View pending pool\n");
    printf(" 5. View active / overdue loans\n");
    printf(" 6. Validate chain integrity\n");
    printf(" 7. Demonstrate tamper detection\n");
    printf(" 8. List books/members registries\n");
    printf(" 9. Mine pending pool — solo\n");
    printf("10. Mine pending pool — pool mining\n");
    printf("11. Mine pending pool — cloud mining\n");
    printf("12. Set mining difficulty (1-4)\n");
    printf("13. View token balances / UTXO set\n");
    printf("14. Transfer tokens between members\n");
    printf("15. View transaction history for a member\n");
    printf(" 0. Exit\n");
    printf("Choose an option: ");
}

static LedgerModel choose_model(void) {
    char choice[8];
    printf("Choose the token ledger model for this session:\n");
    printf("  1. UTXO (inputs/outputs, like Bitcoin)\n");
    printf("  2. Account balances with nonces (like Ethereum)\n");
    printf("Enter 1 or 2: ");
    read_line(choice, sizeof(choice));
    return (choice[0] == '2') ? MODEL_ACCOUNT : MODEL_UTXO;
}

int main(void) {
    srand((unsigned)time(NULL));

    printf("Loading registries...\n");
    if (!load_books(BOOKS_FILE) || !load_members(MEMBERS_FILE)) {
        printf("Startup aborted: fix the registry files and re-run.\n");
        return 1;
    }
    printf("Loaded %d book(s) and %d member(s).\n", g_book_count, g_member_count);

    g_model = choose_model();
    init_accounts();

    g_key = load_or_create_key(KEY_FILE);

    blocks_init(&g_chain);
    blocks_init(&g_pending);
    load_chain(CHAIN_FILE);
    if (g_chain.count > 0) printf("Loaded existing chain with %d confirmed block(s).\n", g_chain.count);
    else printf("Starting a fresh chain (first mined block will be the genesis block).\n");

    int running = 1;
    while (running) {
        print_menu();
        int choice;
        if (scanf("%d", &choice) != 1) { while (getchar() != '\n'); continue; }
        while (getchar() != '\n');

        char book_id[20], member_id[20], recipient_id[20];
        int amount; unsigned long nonce;

        switch (choice) {
            case 1:
                printf("Book ID: "); read_line(book_id, sizeof(book_id));
                printf("Member ID: "); read_line(member_id, sizeof(member_id));
                borrow_book(book_id, member_id);
                break;
            case 2:
                printf("Book ID: "); read_line(book_id, sizeof(book_id));
                printf("Member ID: "); read_line(member_id, sizeof(member_id));
                return_book(book_id, member_id);
                break;
            case 3: view_chain(); break;
            case 4: view_pending(); break;
            case 5: list_active_loans(); break;
            case 6: {
                int ok = validate_chain(1);
                printf("\nOverall chain status: %s\n", ok ? "VALID" : "TAMPERED / CORRUPT");
                break;
            }
            case 7: tamper_demo(); break;
            case 8:
                printf("\nBooks:\n");
                for (int i = 0; i < g_book_count; i++)
                    printf("  %-8s %-30s %s\n", g_books[i].book_id, g_books[i].title, g_books[i].author);
                printf("\nMembers:\n");
                for (int i = 0; i < g_member_count; i++)
                    printf("  %-8s %-25s %s\n", g_members[i].member_id, g_members[i].full_name, g_members[i].course_code);
                break;
            case 9: mine_solo(); save_chain(CHAIN_FILE); break;
            case 10: mine_pool(); save_chain(CHAIN_FILE); break;
            case 11: mine_cloud(); save_chain(CHAIN_FILE); break;
            case 12:
                printf("New difficulty (1-4): ");
                if (scanf("%d", &g_difficulty) == 1) {
                    if (g_difficulty < 1) g_difficulty = 1;
                    if (g_difficulty > 4) g_difficulty = 4;
                }
                while (getchar() != '\n');
                printf("Difficulty set to %d.\n", g_difficulty);
                break;
            case 13:
                if (g_model == MODEL_UTXO) print_utxo_set(); else print_account_balances();
                break;
            case 14:
                printf("Sender member ID: "); read_line(member_id, sizeof(member_id));
                printf("Recipient member ID: "); read_line(recipient_id, sizeof(recipient_id));
                printf("Amount: ");
                if (scanf("%d", &amount) != 1) { while (getchar() != '\n'); break; }
                while (getchar() != '\n');
                if (g_model == MODEL_UTXO) {
                    utxo_transfer(member_id, recipient_id, amount);
                } else {
                    printf("Nonce for this transfer: ");
                    if (scanf("%lu", &nonce) != 1) { while (getchar() != '\n'); break; }
                    while (getchar() != '\n');
                    account_transfer(member_id, recipient_id, amount, nonce);
                }
                break;
            case 15:
                if (g_model != MODEL_ACCOUNT) { printf("Transaction history is tracked under the account-balance model. UTXO owners are visible in option 13.\n"); break; }
                printf("Member ID: "); read_line(member_id, sizeof(member_id));
                print_tx_history(member_id);
                break;
            case 0: running = 0; break;
            default: printf("Unknown option.\n");
        }
    }

    free(g_chain.blocks);
    free(g_pending.blocks);
    EC_KEY_free(g_key);
    printf("Goodbye.\n");
    return 0;
}
