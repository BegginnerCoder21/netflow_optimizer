#ifndef DIJKSTRA_H
#define DIJKSTRA_H

/* =========================================================
 * dijkstra.h - Module 2A : Algorithmes de Routage Optimal
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 *
 * Algorithmes implementes :
 *   1. Dijkstra avec file de priorite (liste chainee)
 *      Complexite : O((V + E) log V)
 *   2. Bellman-Ford
 *      Complexite : O(V * E)
 *   3. Comparaison et benchmarks
 * ========================================================= */

#include "graphe.h"

/* =========================================================
 * Noeud de la file de priorite interne a Dijkstra
 * (Liste chainee triee par distance)
 * ========================================================= */
typedef struct NoeudFilePrio {
    int   id_noeud;
    float distance;
    struct NoeudFilePrio* suivant;
} NoeudFilePrio;

typedef struct FilePriorite {
    NoeudFilePrio* tete;
    int            taille;
} FilePriorite;

/* =========================================================
 * Structure de resultat complet d'un algorithme de routage
 * ========================================================= */
typedef struct ResultatRoutage {
    float*  distances;      /* distances[i] = dist optimale src->i */
    int*    predecesseurs;  /* pred[i] = noeud precedent sur chemin */
    int     nb_noeuds;
    double  temps_exec_ms;  /* Temps d'execution mesure            */
    int     source;
    char    nom_algo[50];
} ResultatRoutage;

/* =========================================================
 * Fonctions - File de priorite interne (pour Dijkstra)
 * ========================================================= */
FilePriorite* fp_creer(void);
void          fp_inserer(FilePriorite* fp, int id, float dist); /* O(n) */
NoeudFilePrio* fp_extraire_min(FilePriorite* fp);               /* O(1) */
void          fp_diminuer_cle(FilePriorite* fp, int id, float nouvelle_dist);
int           fp_est_vide(FilePriorite* fp);
void          fp_liberer(FilePriorite* fp);

/* =========================================================
 * Fonctions - Dijkstra
 * ========================================================= */

/**
 * @brief Algorithme de Dijkstra - plus courts chemins depuis source
 *
 * Utilise une file de priorite implementee avec une liste chainee triee.
 * ATTENTION : Ne fonctionne pas avec des poids negatifs.
 *
 * Analyse de complexite detaillee :
 *   - Initialisation        : O(V)
 *   - Boucle principale     : V iterations
 *     * Extraction min      : O(1) (tete de la liste triee)
 *     * Mise a jour voisins : O(degre(u)) par noeud
 *     * fp_inserer          : O(V) dans le pire cas
 *   - Total                 : O(V^2) avec liste chainee
 *                             O((V+E) log V) avec tas binaire
 *   - Espace                : O(V)
 *
 * @param g       Graphe ponderede
 * @param source  ID du noeud source
 * @return ResultatRoutage* contenant distances et predecesseurs
 */
ResultatRoutage* dijkstra(Graphe* g, int source);

/**
 * @brief Reconstruit le chemin depuis source vers destination
 * @param resultat  Resultat de dijkstra()
 * @param dest      ID du noeud destination
 * @param g         Graphe (pour les metriques)
 * @return Chemin* ou NULL si inaccessible
 */
Chemin* reconstruire_chemin(ResultatRoutage* resultat, int dest, Graphe* g);

/* =========================================================
 * Fonctions - Bellman-Ford
 * ========================================================= */

/**
 * @brief Algorithme de Bellman-Ford - supporte poids negatifs
 *
 * Analyse de complexite detaillee :
 *   - Initialisation        : O(V)
 *   - Boucle principale     : V-1 iterations
 *     * Parcours aretes     : O(E) par iteration
 *   - Detection cycle negatif : O(E)
 *   - Total                 : O(V * E)
 *   - Espace                : O(V)
 *
 * Comparaison avec Dijkstra :
 *   - Avantage  : Supporte les poids negatifs
 *   - Inconvenient : Plus lent O(VE) vs O((V+E)logV)
 *
 * @param g       Graphe (peut avoir des poids negatifs)
 * @param source  ID du noeud source
 * @return ResultatRoutage*, ou NULL si cycle negatif detecte
 */
ResultatRoutage* bellman_ford(Graphe* g, int source);

/* =========================================================
 * Fonctions - Affichage et comparaison
 * ========================================================= */

/** @brief Affiche tous les plus courts chemins depuis source */
void afficher_tous_chemins(ResultatRoutage* r, Graphe* g);

/** @brief Affiche le chemin specifique src->dest */
void afficher_chemin_detail(ResultatRoutage* r, int dest, Graphe* g);

/**
 * @brief Compare Dijkstra et Bellman-Ford sur meme graphe
 * Affiche : distances, temps d'execution, differences
 */
void comparer_dijkstra_bellman(Graphe* g, int source);

/** @brief Libere un ResultatRoutage */
void liberer_resultat_routage(ResultatRoutage* r);

#endif /* DIJKSTRA_H */
