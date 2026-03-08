# NetFlow Optimizer & Security Analyzer

**Projet ALC2101 - Algorithmique et Complexite**
**UVCI - Master Informatique - 2025-2026**

## Compilation

```bash
make          # Compilation normale
make debug    # Avec symboles de debogage
make test     # Tests unitaires
make clean    # Nettoyage
```

## Utilisation

```bash
./netflow
```

## Structure

- `src/graphe.c/.h`         — Module 1 : Modelisation reseau (graphes)
- `src/dijkstra.c/.h`       — Module 2A : Dijkstra + Bellman-Ford
- `src/backtracking.c/.h`   — Module 2B : Chemins contraints + K chemins
- `src/securite.c/.h`       — Module 3 : Detection anomalies (DFS/BFS, SCC)
- `src/liste_chainee.c/.h`  — Module 4 : File de priorite + simulation flux
- `src/utils.c/.h`          — Utilitaires transversaux
- `src/main.c`              — Menu interactif principal
- `tests/tests_unitaires.c` — Tests unitaires exhaustifs
- `data/`                   — Fichiers de reseaux de test
