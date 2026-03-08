#ifndef SECURITE_H
#define SECURITE_H

/* =========================================================
 * securite.h - Module 3 : Detection d'Anomalies et Securite
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "graphe.h"

/* =========================================================
 * RESULTAT DE SECURITE - Rapport complet
 * ========================================================= */
typedef struct ResultatSecurite {
    /* Points d'articulation */
    int* points_articulation;
    int  nb_points_articulation;

    /* Ponts critiques (aretes) */
    int* ponts_src;
    int* ponts_dst;
    int  nb_ponts;

    /* Detection de cycles */
    int  a_des_cycles;
    int  nb_cycles_detectes;

    /* Composantes fortement connexes (Kosaraju) */
    int* composante_id;     /* composante_id[i] = numero de SCC du noeud i */
    int  nb_composantes;

    /* Connectivite */
    int  est_connexe;
    int  est_fortement_connexe;

    double temps_exec_ms;
} ResultatSecurite;

/* =========================================================
 * Fonctions - Parcours DFS / BFS
 * ========================================================= */

/**
 * @brief Parcours en profondeur (DFS) depuis un noeud
 * @complexity O(V + E)
 */
void dfs(Graphe* g, int depart, int* visite);

/**
 * @brief Parcours en largeur (BFS) depuis un noeud
 * @complexity O(V + E)
 */
void bfs(Graphe* g, int depart, int* visite);

/** @brief Affiche l'ordre de visite DFS */
void dfs_affichage(Graphe* g, int depart);

/** @brief Affiche l'ordre de visite BFS */
void bfs_affichage(Graphe* g, int depart);

/* =========================================================
 * Fonctions - Detection de cycles
 * ========================================================= */

/**
 * @brief Detecte la presence de cycles dans le graphe
 *
 * Methode : DFS avec coloration (blanc/gris/noir)
 *   - Blanc (0) : non visite
 *   - Gris  (1) : en cours de visite (dans la pile DFS)
 *   - Noir  (2) : visite complet
 *
 * Un cycle existe si on rencontre un noeud gris.
 *
 * @complexity O(V + E)
 * @return 1 si cycle detecte, 0 sinon
 */
int detecter_cycles(Graphe* g);

/** Fonction recursive interne pour la detection */
int dfs_cycle(Graphe* g, int u, int* couleur);

/* =========================================================
 * Fonctions - Points d'articulation et ponts
 * ========================================================= */

/**
 * @brief Calcule les points d'articulation par DFS modifie
 *
 * Utilise les valeurs "discovery time" et "low value" :
 *   - disc[u] = temps de decouverte de u
 *   - low[u]  = min disc dans le sous-arbre DFS de u
 *
 * u est un point d'articulation si :
 *   1. u est la racine DFS et a >= 2 enfants
 *   2. u n'est pas la racine et low[enfant] >= disc[u]
 *
 * @complexity O(V + E)
 */
void trouver_points_articulation(Graphe* g,
                                  int* points_artic,
                                  int* nb_points);

/** Fonction DFS recursive interne */
void dfs_articulation(Graphe* g, int u, int parent,
                       int* disc, int* low, int* visite,
                       int* est_artic, int* timer);

/**
 * @brief Identifie les ponts (aretes critiques)
 *
 * Une arete (u,v) est un pont si sa suppression
 * augmente le nombre de composantes connexes.
 *
 * Condition : low[v] > disc[u]
 *
 * @complexity O(V + E)
 */
void trouver_ponts(Graphe* g, int* ponts_src, int* ponts_dst, int* nb_ponts);

/** DFS interne pour les ponts */
void dfs_ponts(Graphe* g, int u, int parent,
               int* disc, int* low, int* visite,
               int* p_src, int* p_dst, int* nb, int* timer);

/* =========================================================
 * Fonctions - Composantes Fortement Connexes (Kosaraju)
 * ========================================================= */

/**
 * @brief Algorithme de Kosaraju pour les SCC
 *
 * =============================================================
 * ALGORITHME DE KOSARAJU - 2 passes DFS
 * =============================================================
 * 1. DFS sur le graphe original -> ordre de fin de visite (pile)
 * 2. Transposer le graphe (inverser toutes les aretes)
 * 3. DFS sur le graphe transpose dans l'ordre inverse de fin
 *    -> chaque DFS identifie une SCC
 *
 * Complexite :
 *   - Passe 1 (DFS original)   : O(V + E)
 *   - Transposition            : O(V + E)
 *   - Passe 2 (DFS transpose)  : O(V + E)
 *   - Total                    : O(V + E)
 * =============================================================
 *
 * @param g              Graphe oriente
 * @param composante_id  composante_id[i] = id SCC du noeud i
 * @return Nombre de SCC
 */
int kosaraju(Graphe* g, int* composante_id);

/** DFS avec remplissage de la pile (ordre de fin) */
void dfs_kosaraju_passe1(Graphe* g, int u, int* visite, Pile* pile);

/** DFS sur graphe transpose pour identifier une SCC */
void dfs_kosaraju_passe2(Graphe* g_transposee, int u, int* visite, int scc_id, int* comp_id);

/** @brief Construit le graphe transpose (inversion des aretes) */
Graphe* transposer_graphe(Graphe* g);

/* =========================================================
 * Fonctions - Rapport complet
 * ========================================================= */

/**
 * @brief Genere un rapport de securite complet
 * Execute tous les algorithmes et synthetise les resultats
 * @complexity O(V + E) - domine par les algorithmes lineaires
 */
ResultatSecurite* analyser_securite_complete(Graphe* g);

/** @brief Affiche le rapport de securite complet */
void afficher_rapport_securite(ResultatSecurite* r, Graphe* g);

/** @brief Libere un ResultatSecurite */
void liberer_resultat_securite(ResultatSecurite* r);

#endif /* SECURITE_H */
