#ifndef BACKTRACKING_H
#define BACKTRACKING_H

/* =========================================================
 * backtracking.h - Module 2B : Chemins Contraints + K chemins
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "graphe.h"

#define K_MAX_CHEMINS  10  /* Nombre maximum de chemins alternatifs */

/* =========================================================
 * CONTRAINTES - Ensemble de restrictions pour le chemin
 * ========================================================= */
typedef struct Contraintes {
    float bande_passante_min;   /* BP minimum garantie (Mbps)          */
    float cout_max;             /* Cout maximum autorise               */
    int   securite_min;         /* Niveau securite minimum (0-10)      */
    int*  noeuds_oblg;          /* Tableau des noeuds obligatoires      */
    int   nb_noeuds_oblg;
    int*  noeuds_exclus;        /* Tableau des noeuds interdits         */
    int   nb_noeuds_exclus;
    int   optimiser_latence;    /* 1=minimiser latence, 0=minimiser cout */
} Contraintes;

/* =========================================================
 * Contexte interne du backtracking (evite les variables globales)
 * ========================================================= */
typedef struct ContexteBacktrack {
    Graphe*      g;
    int          source;
    int          destination;
    Contraintes* contraintes;
    int*         visite;           /* Tableau des noeuds visites        */
    int*         chemin_courant;   /* Pile du chemin en cours           */
    int          longueur_courante;
    float        latence_courante;
    float        cout_courant;
    float        bp_min_courante;
    Chemin*      meilleur;         /* Meilleur chemin trouve            */
    int          nb_solutions;     /* Compteur de solutions valides     */
    int          nb_appels;        /* Compteur d'appels recursifs       */
} ContexteBacktrack;

/* =========================================================
 * Fonctions - Contraintes
 * ========================================================= */
Contraintes* creer_contraintes(float bp_min, float cout_max, int sec_min);
void ajouter_noeud_oblg(Contraintes* c, int id_noeud);
void ajouter_noeud_exclu(Contraintes* c, int id_noeud);
void afficher_contraintes(Contraintes* c);
void liberer_contraintes(Contraintes* c);

/* =========================================================
 * Fonctions - Backtracking
 * ========================================================= */

/**
 * @brief Recherche un chemin avec contraintes multiples par backtracking
 *
 * =============================================================
 * ANALYSE DE COMPLEXITE
 * =============================================================
 * Soit b = facteur de branchement (degre moyen)
 *      d = profondeur de la solution (longueur du chemin)
 *
 * Sans elagage : O(b^d) - exploration exhaustive de l'arbre
 *
 * Avec elagage (pruning), on coupe les branches quand :
 *   1. Le noeud est deja visite (evite cycles)
 *   2. Noeud exclu par contraintes
 *   3. La BP de l'arete < BP_min (coupe immediate)
 *   4. Le cout accumule > cout_max (coupe par borne)
 *   5. Le niveau de securite < sec_min
 *
 * En pratique, l'elagage reduit considerablement le temps,
 * mais le pire cas reste O(b^d) (NP-complet en general).
 * =============================================================
 *
 * @param g      Graphe
 * @param src    Noeud source
 * @param dest   Noeud destination
 * @param c      Contraintes (NULL = aucune contrainte)
 * @return Meilleur chemin satisfaisant les contraintes, NULL si aucun
 */
Chemin* chemin_contraint_backtracking(Graphe* g, int src, int dest, Contraintes* c);

/**
 * @brief Trouve les K meilleurs chemins (sans repetition de noeuds)
 *
 * Approche Diviser pour Regner :
 *   - Trouver le 1er chemin optimal (Dijkstra)
 *   - Pour chaque chemin suivant : explorer les variantes
 *     en supprimant temporairement des aretes du precedent
 *
 * Complexite : O(K * (V + E) * log V)
 *
 * @param g     Graphe
 * @param src   Source
 * @param dest  Destination
 * @param k     Nombre de chemins desires
 * @return Tableau de k Chemin* (certains peuvent etre NULL)
 */
Chemin** k_plus_courts_chemins(Graphe* g, int src, int dest, int k);

/** @brief Affiche les K chemins avec comparaison */
void afficher_k_chemins(Chemin** chemins, int k, Graphe* g);

/** @brief Libere le tableau de K chemins */
void liberer_k_chemins(Chemin** chemins, int k);

/* Fonction recursive interne */
void backtrack_recursif(ContexteBacktrack* ctx, int noeud_courant);

/* Verification des contraintes */
int contraintes_satisfaites(ContexteBacktrack* ctx, int dest);

#endif /* BACKTRACKING_H */
