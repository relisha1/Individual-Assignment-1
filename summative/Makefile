CC       = gcc
CFLAGS   = -Wall -Wextra -std=c11 -Iinclude -Wno-deprecated-declarations
LDFLAGS  = -lcrypto

SRC      = src/main.c
BIN      = lending_tracker

all: $(BIN)

$(BIN): $(SRC) include/openssl_compat.h
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

run: all
	./$(BIN)

clean:
	rm -f $(BIN) chain.dat copy_state.dat reservations.dat pool.dat utxo.dat accounts.dat member_nonces.dat fines.dat meta.dat member_keys.dat

.PHONY: all run clean
