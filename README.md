# Library Blockchain Lending Tracker

A blockchain-based library book lending ledger written in C. Every borrow
and return is stored as a block, chained to the previous block with a
SHA-256 hash and signed with an ECDSA (P-256) key, so past records cannot
be silently edited without detection.

## Required libraries and dependencies

- **gcc** (or any C11 compiler) and **make**
- **OpenSSL runtime library** (`libcrypto.so` / `libcrypto.so.3`) — present
  by default on almost all Linux distributions and macOS (via Homebrew's
  `openssl`). No `libssl-dev` / header package is required: this project
  hand-declares the small number of OpenSSL functions it calls in
  `include/openssl_compat.h`, and links straight against the runtime
  library. See the comment block at the top of that file for details and
  for how to switch to the real `<openssl/...>` headers if you do have
  the dev package installed.

Tested on Ubuntu 24.04 with gcc 13 and OpenSSL 3.0.

## Project layout

```
.
├── Makefile
├── README.md
├── include/
│   └── openssl_compat.h   # minimal hand-declared OpenSSL prototypes
├── src/
│   └── main.c             # entire application
└── data/
    ├── books.txt          # sample book registry
    └── members.txt        # sample member registry
```

## Build

```bash
make
```

This produces an executable called `lending_tracker`.

## Run

The program looks for `books.txt` and `members.txt` in the **current
working directory**. Copy the sample registries in first, or point it at
your own files with the same names/format:

```bash
cp data/books.txt data/members.txt .
make run          # builds (if needed) and runs ./lending_tracker
# or, once built:
./lending_tracker
```

On first run the program will:
1. Load and validate `books.txt` and `members.txt`.
2. Generate an ECDSA P-256 keypair and save it to `library_key.der` (reused
   on every subsequent run so all signatures verify against the same key).
3. Create the genesis block (index 0, `previous_hash` = 64 zeros).

The chain is persisted to `blockchain.dat` after every borrow/return and
reloaded automatically the next time you launch the program, so lending
history survives restarts.

## Registry file format

`books.txt` — one book per line: `book_id,title,author`
```
BK001,Things Fall Apart,Chinua Achebe
```

`members.txt` — one member per line: `member_id,full_name,course_code`
```
ALU001,John Doe,BLK101
```

## Using the CLI

```
1. Borrow a book        -> prompts for Book ID and Member ID
2. Return a book        -> prompts for Book ID and Member ID
3. View all lending records
4. Validate chain integrity      -> recomputes every hash, link, signature
5. Demonstrate tamper detection  -> edits a past block in memory and shows
                                     validation failing (does not touch
                                     blockchain.dat)
6. List books/members registries
0. Exit
```

Borrowing or returning with a `book_id`/`member_id` not present in the
registries prints `ERROR: Book or Member not found` and nothing is
recorded. Trying to borrow a book that's already out, or return a book
with no active loan, is also rejected with a clear error.

## Cleaning up

```bash
make clean   # removes the binary, blockchain.dat and library_key.der
```
