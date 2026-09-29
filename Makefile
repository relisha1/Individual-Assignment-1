CC       = gcc
CFLAGS   = -Wall -Wextra -std=c11 -Iinclude -Wno-deprecated-declarations
# libssl-dev is not required: openssl_compat.h hand-declares the few
# libcrypto symbols we use, and we link straight against the runtime
# library. If you DO have libssl-dev installed, `-lcrypto` can
# be replaced with `-lcrypto` and openssl_compat.h's includes swapped
# for the real <openssl/...> headers — see the comment at the top of
# openssl_compat.h.
LDFLAGS  = -lcrypto

SRC      = src/main.c
BIN      = lending_tracker

all: $(BIN)

$(BIN): $(SRC) include/openssl_compat.h
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

run: all
	./$(BIN)

clean:
	rm -f $(BIN) blockchain.dat library_key.der

.PHONY: all run clean
