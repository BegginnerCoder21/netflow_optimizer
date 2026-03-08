#ifndef GRAPHE_H
#define GRAPHE_H

/* =========================================================
 * graphe.h - Module 1 : Modelisation du Reseau
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 *
 * Deux representations implementees :
 *   1. Listes d'adjacence (graphes creux)
 *   2. Matrice d'adjacence (graphes denses)
 * ========================================================= */

#include "utils.h"
#include "liste_chainee.h"

/* =========================================================
 * ARETE - Noeud de liste d'adjacence
 * Chaque arete possede 4 metriques de ponderation
 * ========================================================= */
typedef struct Arete {
    int   destination;      /* ID du noeud destination         */
    float latence;          /* Delai en millisecondes (ms)     */
    float bande_passante;   /* Capacite en Mbps                */
    float cout;             /* Cout monetaire (unite arbitraire)*/
    int   securite;         /* Niveau securite : 0 (faible) a 10 (fort) */
    struct Arete* suivant;  /* Maillon suivant dans la liste   */
} Arete;

/* =========================================================
 * NOEUD - Sommet du graphe
 * ========================================================= */
typedef struct Noeud {
    int   id;                       /* Identifiant unique      */
    char  nom[TAILLE_MAX_NOM];      /* Nom lisible             */
    Arete* aretes;                  /* Tete de liste d'adjacence */
    int   degre_sortie;             /* Nombre d'aretes sortantes */
    int   degre_entree;             /* Nombre d'aretes entrantes */
} Noeud;

/* =========================================================
 * GRAPHE - Structure principale
 * Supporte les deux representations simultanement
 * ========================================================= */
typedef struct Graphe {
    int    nb_noeuds;               /* Nombre de sommets actifs  */
    int    nb_aretes;               /* Nombre d'aretes total     */
    int    capacite;                /* Capacite max allouee      */
    int    est_oriente;             /* 1=oriente, 0=non-oriente  */
    Noeud* noeuds;                  /* Tableau de noeuds         */
    float** matrice_adjacence;      /* Matrice n x n (latences)  */
} Graphe;

/* =========================================================
 * Fonctions - Creation et destruction
 * ========================================================= */

/**
 * @brief Cree et initialise un graphe
 * @param nb_noeuds  Nombre de sommets
 * @param est_oriente 1 pour graphe oriente, 0 sinon
 * @return Pointeur vers le graphe alloue
 * @complexity O(V^2) pour l'allocation de la matrice
 */
Graphe* creer_graphe(int nb_noeuds, int est_oriente);

/**
 * @brief Libere toute la memoire du graphe
 * @complexity O(V + E)
 */
void detruire_graphe(Graphe* g);

/* =========================================================
 * Fonctions - Modification du graphe
 * ========================================================= */

/**
 * @brief Ajoute un noeud au graphe
 * @complexity O(1)
 */
void ajouter_noeud(Graphe* g, int id, const char* nom);

/**
 * @brief Ajoute une arete orientee (ou double si non-oriente)
 * @complexity O(1) pour la liste, O(1) pour la matrice
 */
void ajouter_arete(Graphe* g, int src, int dest,
                   float latence, float bande_passante,
                   float cout, int securite);

/**
 * @brief Supprime un noeud et toutes ses aretes
 * @complexity O(V + E)
 */
void supprimer_noeud(Graphe* g, int id);

/**
 * @brief Supprime une arete specifique
 * @complexity O(degre(src))
 */
void supprimer_arete(Graphe* g, int src, int dest);

/* =========================================================
 * Fonctions - Persistance
 * ========================================================= */

/**
 * @brief Charge un graphe depuis un fichier texte structure
 * Format du fichier :
 *   # commentaire
 *   NOEUDS <n>
 *   <id> <nom>
 *   ...
 *   ARETES <m>
 *   <src> <dst> <latence> <bande_passante> <cout> <securite>
 *   ...
 * @return Pointeur vers graphe charge, NULL si erreur
 */
Graphe* charger_graphe_fichier(const char* chemin);

/**
 * @brief Sauvegarde le graphe dans un fichier texte
 * @complexity O(V + E)
 */
void sauvegarder_graphe(Graphe* g, const char* chemin);

/* =========================================================
 * Fonctions - Affichage
 * ========================================================= */

/** @brief Affiche le graphe sous forme de liste d'adjacence */
void afficher_graphe(Graphe* g);

/** @brief Affiche la matrice d'adjacence (latences) */
void afficher_matrice(Graphe* g);

/** @brief Affiche les informations d'un noeud */
void afficher_noeud(Graphe* g, int id);

/* =========================================================
 * Fonctions - Utilitaires
 * ========================================================= */

/** @brief Verifie si une arete existe entre src et dest */
int arete_existe(Graphe* g, int src, int dest);

/** @brief Retourne l'arete entre src et dest, NULL si inexistante */
Arete* obtenir_arete(Graphe* g, int src, int dest);

/** @brief Met a jour la matrice depuis les listes d'adjacence */
void mettre_a_jour_matrice(Graphe* g);

/** @brief Genere un graphe aleatoire connexe */
Graphe* generer_graphe_aleatoire(int nb_noeuds, float densite, int est_oriente);

/** @brief Retourne le nom d'un noeud par son id */
const char* obtenir_nom_noeud(Graphe* g, int id);

/** @brief Verifie si un id de noeud est valide */
int noeud_valide(Graphe* g, int id);

#endif /* GRAPHE_H */
