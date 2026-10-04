# Library Blockchain Lending Tracker — Formative 2

Extends the Formative 1 tracker so that returning a book earns the member
token rewards, and lending blocks only become permanent once a miner
confirms them. Supports two ways of tracking member balances (UTXO or
account-based) and three mining simulations (solo, pool, cloud).

## What's new since Formative 1

- Returning a book **on time** earns the member **10 tokens**; returning it
  **late** earns **5 tokens**; a book that's never returned earns nothing.
- Borrow/return events no longer go straight onto the chain. They sit in a
  **pending pool** until a miner confirms them — only then is the record
  permanent and the reward actually credited.
- Two interchangeable models for tracking who owns what:
  - **UTXO** — like Bitcoin. Tokens exist as discrete "unspent outputs";
    spending them creates new outputs and returns any leftover as change.
  - **Account balances** — like a bank account / Ethereum. Each member has
    a running balance and a nonce that must be used in order.
- Three mining simulations, all confirming the same pending pool:
  - **Solo** — real proof-of-work: the program searches nonces and
    recomputes SHA-256 until the hash has enough leading zeros.
  - **Pool** — splits the real hash-attempt count across a handful of
    simulated miners by random hash power, after a 2% pool fee.
  - **Cloud** — a multi-round rental simulation with a fee each round and
    a warning if the rental stops being profitable.

## Required libraries and dependencies

- **gcc** and **make**
- **OpenSSL runtime** (`libcrypto`). No `libssl-dev` headers are required —
  `include/openssl_compat.h` hand-declares the handful of functions used
  (SHA-256 and ECDSA) and links straight against the runtime library. See
  the comment at the top of that file for how to switch to the real
  `<openssl/...>` headers if you have `libssl-dev` installed.

## Project layout

```
.
├── Makefile
├── README.md
├── include/
│   └── openssl_compat.h
├── src/
│   └── main.c
└── data/
    ├── books.txt
    └── members.txt
```

## Build

```bash
make
```

## Run

```bash
cp data/books.txt data/members.txt .
./lending_tracker
```

The program first asks which ledger model to use for the session:
```
Choose the token ledger model for this session:
  1. UTXO (inputs/outputs, like Bitcoin)
  2. Account balances with nonces (like Ethereum)
```
This choice applies to every token transaction for the rest of the run.
Starting the program again lets you pick the other model — member
balances are recalculated by replaying the confirmed chain under
whichever model is currently selected, so switching models between runs
is safe.

## How to set mining difficulty

Difficulty controls how many leading hex zero characters a block's hash
must have before it's accepted (default: 2). Higher difficulty means more
hash attempts, so mining takes longer.

- From the menu, option **12** lets you change it at any time (1 to 4).
- There is no command-line flag for it — it's set interactively so you can
  raise or lower it mid-session and see the effect immediately on the
  next mining run.

## How to test the mining simulations

1. Borrow and return a couple of books (menu options 1 and 2) so the
   pending pool has something in it — check with option 4.
2. Run option **9** for solo mining. You'll see the real attempt count per
   block and the final hash.
3. Borrow/return again, then run option **10** for pool mining. You'll be
   asked how many simulated miners to split the work across (2–6), then
   see a reward-sharing table.
4. Borrow/return again, then run option **11** for cloud mining. You'll be
   asked for a rental duration (1–5 rounds); watch the per-round fee and
   reward, and the unprofitability warning if fees outrun rewards.
5. Use option **6** to confirm the chain is still valid after each mining
   run, and option **7** to see tampering get caught.

## How to switch between transaction models

The model is chosen once, right at startup (see above). To compare the
two models side by side, run the program twice in separate sessions —
member balances are derived fresh from the chain each time, so there's no
conflict between runs.

Once a model is active:
- **UTXO**: option 13 prints the full UTXO set and each member's spendable
  balance; option 14 sends tokens by spending UTXOs (with change returned
  automatically); option 15 is not used in this mode (UTXO ownership is
  already visible in option 13).
- **Account**: option 13 prints each member's balance and next expected
  nonce; option 14 sends tokens and requires the correct nonce; option 15
  prints a member's full transaction history.

## A couple of deliberate design choices worth knowing about

- **Loan period is 20 seconds, not 14 days.** This is so a late return can
  be demonstrated live in a short recording instead of waiting two weeks.
  To use a realistic period, change `LOAN_PERIOD_SECONDS` in `src/main.c`.
- **UTXO transfers (option 14 under the UTXO model) aren't written to
  `blockchain.dat`.** Only the lending blocks (borrow/return/mining) are
  persisted. If you restart the program, token *rewards* reappear (they're
  replayed from the chain), but any manual *transfers* you made in the
  previous session are not. This is documented in the technical report.
- **The solo/pool/cloud mining reward is reported, not credited to any
  member.** A miner isn't necessarily a library member, so the reward is
  shown on screen as a demonstration of the mechanism rather than added to
  someone's balance.

## Cleaning up

```bash
make clean   # removes the binary, blockchain.dat and library_key.der
```
