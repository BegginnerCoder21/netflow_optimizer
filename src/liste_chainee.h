#ifndef LISTE_CHAINEE_H
#define LISTE_CHAINEE_H

/* =========================================================
 * liste_chainee.h - Structures de listes chainees
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 *
 * Structures implementees FROM SCRATCH (sans bibliotheques) :
 *  - Paquet (noeud doublement chaine)
 *  - FileAttente (file de priorite doublement chainee)
 *  - Pile (pour DFS et backtracking)
 *  - File simple (pour BFS)
 *  - NoeudChemin (liste chainee de noeuds de chemin)
 * ========================================================= */

#include "utils.h"

/* =========================================================
 * PAQUET - Noeud de la liste doublement chainee
 * Represente un paquet reseau en attente de traitement
 * ========================================================= */
typedef struct Paquet {
    int   id;            /* Identifiant unique du paquet       */
    int   priorite;      /* Priorite : 1 (faible) a 10 (haute) */
    float taille_Mo;     /* Taille en megaoctets               */
    int   source;        /* ID du noeud source                 */
    int   destination;   /* ID du noeud destination            */
    double temps_arrivee;/* Temps d'arrivee (ms)               */
    struct Paquet* precedent; /* Pointeur vers paquet precedent */
    struct Paquet* suivant;   /* Pointeur vers paquet suivant   */
} Paquet;

/* =========================================================
 * FILE D'ATTENTE - File de priorite doublement chainee
 * ========================================================= */
typedef struct FileAttente {
    Paquet* tete;          /* Pointeur vers le premier paquet  */
    Paquet* queue;         /* Pointeur vers le dernier paquet  */
    int     taille_actuelle;
    int     capacite_max;
} FileAttente;

/* =========================================================
 * STATISTIQUES DE FLUX
 * ========================================================= */
typedef struct StatistiquesFlux {
    float  temps_moyen_attente; /* Temps moyen en file (ms)    */
    float  taux_perte;          /* Pourcentage de paquets perdus */
    float  debit_effectif;      /* Mbps effectivement traites  */
    int    paquets_traites;
    int    paquets_perdus;
    int    paquets_total;
} StatistiquesFlux;

/* =========================================================
 * PILE - Pour DFS et backtracking
 * ========================================================= */
typedef struct NoeudPile {
    int valeur;
    struct NoeudPile* suivant;
} NoeudPile;

typedef struct Pile {
    NoeudPile* sommet;
    int        taille;
} Pile;

/* =========================================================
 * FILE SIMPLE - Pour BFS
 * ========================================================= */
typedef struct NoeudFile {
    int valeur;
    struct NoeudFile* suivant;
} NoeudFile;

typedef struct FileBFS {
    NoeudFile* tete;
    NoeudFile* queue;
    int        taille;
} FileBFS;

/* =========================================================
 * NOEUD DE CHEMIN - Pour stocker les chemins trouves
 * ========================================================= */
typedef struct NoeudChemin {
    int id_noeud;
    struct NoeudChemin* suivant;
} NoeudChemin;

typedef struct Chemin {
    NoeudChemin* noeuds;       /* Liste chainee des noeuds    */
    float latence_totale;
    float cout_total;
    float bande_passante_min;  /* Goulot d'etranglement       */
    int   longueur;            /* Nombre de noeuds            */
} Chemin;

/* =========================================================
 * Fonctions - FileAttente (file de priorite)
 * ========================================================= */
FileAttente* creer_file(int capacite_max);

/**
 * @brief Insere un paquet dans la file par ordre de priorite decroissante
 * @complexity O(n) - insertion triee dans liste chainee
 */
void enqueue(FileAttente* f, Paquet* p);

/**
 * @brief Extrait le paquet de plus haute priorite (tete)
 * @complexity O(1) - acces direct a la tete
 */
Paquet* dequeue(FileAttente* f);

/**
 * @brief Consulte le prochain paquet sans le supprimer
 * @complexity O(1)
 */
Paquet* peek(FileAttente* f);

int  file_est_vide(FileAttente* f);
int  file_est_pleine(FileAttente* f);
void afficher_file(FileAttente* f);
void liberer_file(FileAttente* f);

/* =========================================================
 * Fonctions - Paquet
 * ========================================================= */
Paquet* creer_paquet(int id, int priorite, float taille, int src, int dest);
void    liberer_paquet(Paquet* p);

/* =========================================================
 * Fonctions - Pile (LIFO)
 * ========================================================= */
Pile* creer_pile(void);
void  empiler(Pile* p, int valeur);        /* push - O(1) */
int   depiler(Pile* p);                    /* pop  - O(1) */
int   sommet_pile(Pile* p);               /* peek - O(1) */
int   pile_est_vide(Pile* p);
void  liberer_pile(Pile* p);

/* =========================================================
 * Fonctions - File BFS (FIFO)
 * ========================================================= */
FileBFS* creer_file_bfs(void);
void     enfiler_bfs(FileBFS* f, int valeur);  /* enqueue - O(1) */
int      defiler_bfs(FileBFS* f);              /* dequeue - O(1) */
int      file_bfs_est_vide(FileBFS* f);
void     liberer_file_bfs(FileBFS* f);

/* =========================================================
 * Fonctions - Chemin
 * ========================================================= */
Chemin*     creer_chemin(void);
void        ajouter_noeud_chemin(Chemin* c, int id_noeud);
Chemin*     copier_chemin(Chemin* c);
void        afficher_chemin(Chemin* c);
void        liberer_chemin(Chemin* c);

/* =========================================================
 * Fonctions - Simulation
 * ========================================================= */
StatistiquesFlux simuler_flux(int nb_paquets, int capacite, int nb_noeuds);
void             afficher_statistiques(StatistiquesFlux* stats);

#endif /* LISTE_CHAINEE_H */
