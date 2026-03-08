# =========================================================
# Makefile - NetFlow Optimizer & Security Analyzer
# Cours  : ALC2101 - Algorithmique et Complexite
# UVCI   - Annee 2025-2026
# =========================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -I src
DFLAGS  = -Wall -Wextra -std=c11 -g -DDEBUG -I src
LDFLAGS = -lm

SRCS = src/utils.c src/liste_chainee.c src/graphe.c \
       src/dijkstra.c src/backtracking.c src/securite.c

TARGET  = netflow
TEST    = netflow_tests

.PHONY: all debug clean test

all: $(TARGET)

$(TARGET): $(SRCS) src/main.c
	$(CC) $(CFLAGS) $(SRCS) src/main.c -o $(TARGET) $(LDFLAGS)
	@echo "[OK] Compilation reussie : ./$(TARGET)"

debug: $(SRCS) src/main.c
	$(CC) $(DFLAGS) $(SRCS) src/main.c -o $(TARGET)_debug $(LDFLAGS)
	@echo "[OK] Build debug : ./$(TARGET)_debug"

test: $(SRCS) tests/tests_unitaires.c
	$(CC) $(CFLAGS) $(SRCS) tests/tests_unitaires.c -o $(TEST) $(LDFLAGS)
	@echo "[OK] Tests compiles. Execution..."
	./$(TEST)

clean:
	rm -f $(TARGET) $(TARGET)_debug $(TEST)
	@echo "[OK] Nettoyage effectue."
