# Library Blockchain Lending Tracker: Summative

The complete system: signed lending records batched into blocks with a Merkle
root, copy-level inventory, reservations, renewals, overdue fines, token
rewards, a pending pool with prioritisation, solo/pool/cloud mining, UTXO and
account-balance ledgers, per-member ECDSA keys, nonce replay protection,
fraud detection, and full disk persistence.

## Dependencies

- gcc and make
- OpenSSL runtime (libcrypto). No dev headers needed: `include/openssl_compat.h`
  declares the few functions used (SHA-256, ECDSA, key serialisation).

On Windows (MSYS2 UCRT64) or any machine with `libssl-dev`, swap in the real
headers and link flag:

```bash
sed -i 's|#include "openssl_compat.h"|#include <openssl/sha.h>\n#include <openssl/ec.h>\n#include <openssl/ecdsa.h>\n#include <openssl/obj_mac.h>|' src/main.c
sed -i 's|-l:libcrypto.so.3|-lcrypto|; s|^CFLAGS.*|CFLAGS   = -Wall -Wextra -std=c11 -Iinclude -Wno-deprecated-declarations|' Makefile
```

## Build and run

```bash
cp data/books.txt data/members.txt data/copies.txt .
make
./lending_tracker
```

The program first asks which ledger model to use (1 or 2), then shows a
numbered menu (borrow, return, mine, and so on). Pick a number and it asks
for the details it needs. Type `m` to show the menu again and `0` to exit.
The underlying commands (`borrow_book`, `mine_solo`, ...) can also be typed
directly at the same prompt. State is saved after each mined block and on
exit, and reloaded (and re-validated) at the next start.

## Switching between UTXO and account models

Chosen at startup: `1` for UTXO, `2` for account balances. It applies to the
whole session. Balances are rebuilt from saved state, so you can restart and
pick the other model.

## Setting mining difficulty

`set_difficulty <1-4>` and `difficulty_status` at the prompt. Difficulty 2 means
the hash must start with `00`, difficulty 4 with `0000`.

## Testing the mining simulations

```
borrow_book BK001 ALU001
borrow_book BK002 ALU002
pool_view
mine_solo            # real proof-of-work, shows attempt count
mine_pool 3          # reward-sharing table across 3 simulated miners
mine_cloud 3         # 3-round rental, fees vs rewards, unprofitable warning
validate_chain
```

## Other useful commands

```
reserve_book BK002 ALU003      renew_book C001 ALU001
check_overdue / view_fines     settle_fine ALU002 2
fraud_review                   approve_suspicious 0 / reject_suspicious 0
tamper_demo 0                  simulate_replay ALU001   (extra: shows nonce rejection)
transaction_history ALU001     utxo_view / account_balance ALU001
```

## Design notes

- Loan, renewal, overdue-unit and rapid re-borrow windows are 20 seconds so
  every case can be shown live. Realistic values are in comments beside the
  constants at the top of `src/main.c`.
- Blocks hold a fixed 3 records.
- Miner rewards are displayed, not credited to any member.
- State files are plain text, one record per line, fields separated by `|`.
