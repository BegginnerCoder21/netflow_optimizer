/* =========================================================
 * liste_chainee.c - Implementation des listes chainees
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "liste_chainee.h"
#include <stdlib.h>
#include <stdio.h>

/* =========================================================
 * PAQUET
 * ========================================================= */

Paquet* creer_paquet(int id, int priorite, float taille, int src, int dest) {
    Paquet* p = (Paquet*)malloc(sizeof(Paquet));
    VERIF_NULL(p, "creer_paquet : allocation echouee");
    p->id          = id;
    p->priorite    = priorite;
    p->taille_Mo   = taille;
    p->source      = src;
    p->destination = dest;
    p->temps_arrivee = obtenir_temps_ms();
    p->precedent   = NULL;
    p->suivant     = NULL;
    return p;
}

void liberer_paquet(Paquet* p) {
    if (p != NULL) free(p);
}

/* =========================================================
 * FILE D'ATTENTE - File de priorite doublement chainee
 * ========================================================= */

FileAttente* creer_file(int capacite_max) {
    FileAttente* f = (FileAttente*)malloc(sizeof(FileAttente));
    VERIF_NULL(f, "creer_file : allocation echouee");
    f->tete           = NULL;
    f->queue          = NULL;
    f->taille_actuelle = 0;
    f->capacite_max   = capacite_max;
    return f;
}

int file_est_vide(FileAttente* f) {
    return (f == NULL || f->taille_actuelle == 0);
}

int file_est_pleine(FileAttente* f) {
    return (f != NULL && f->capacite_max > 0 &&
            f->taille_actuelle >= f->capacite_max);
}

/**
 * @brief Insere un paquet dans la file par priorite decroissante
 *
 * La tete contient toujours le paquet de plus haute priorite.
 * Insertion triee par insertion dans la liste doublement chainee.
 *
 * Analyse de complexite :
 *   - Meilleur cas  : O(1) si priorite la plus haute (insertion en tete)
 *   - Cas moyen     : O(n/2) = O(n)
 *   - Pire cas      : O(n) si priorite la plus basse (insertion en queue)
 */
void enqueue(FileAttente* f, Paquet* p) {
    if (f == NULL || p == NULL) return;

    /* File pleine : paquet perdu */
    if (file_est_pleine(f)) {
        afficher_avertissement("File pleine - paquet perdu");
        liberer_paquet(p);
        return;
    }

    p->precedent = NULL;
    p->suivant   = NULL;

    /* Cas 1 : file vide */
    if (f->tete == NULL) {
        f->tete  = p;
        f->queue = p;
        f->taille_actuelle++;
        return;
    }

    /* Cas 2 : priorite superieure ou egale au premier element */
    if (p->priorite >= f->tete->priorite) {
        p->suivant        = f->tete;
        f->tete->precedent = p;
        f->tete           = p;
        f->taille_actuelle++;
        return;
    }

    /* Cas 3 : insertion triee dans la liste */
    Paquet* courant = f->tete;
    while (courant->suivant != NULL &&
           courant->suivant->priorite > p->priorite) {
        courant = courant->suivant;
    }

    /* Insertion apres courant */
    p->suivant = courant->suivant;
    p->precedent = courant;
    if (courant->suivant != NULL) {
        courant->suivant->precedent = p;
    } else {
        f->queue = p; /* Nouveau dernier element */
    }
    courant->suivant = p;
    f->taille_actuelle++;
}

/**
 * @brief Extrait le paquet de plus haute priorite
 * @complexity O(1) - acces direct a la tete
 */
Paquet* dequeue(FileAttente* f) {
    if (file_est_vide(f)) return NULL;

    Paquet* p = f->tete;
    f->tete = f->tete->suivant;

    if (f->tete != NULL) {
        f->tete->precedent = NULL;
    } else {
        f->queue = NULL;
    }

    p->suivant   = NULL;
    p->precedent = NULL;
    f->taille_actuelle--;
    return p;
}

/**
 * @brief Consultation sans extraction
 * @complexity O(1)
 */
Paquet* peek(FileAttente* f) {
    if (file_est_vide(f)) return NULL;
    return f->tete;
}

void afficher_file(FileAttente* f) {
    if (file_est_vide(f)) {
        afficher_info("File vide.");
        return;
    }
    printf("\n  File d'attente (%d/%d paquets) :\n",
           f->taille_actuelle, f->capacite_max);
    printf("  %-6s %-10s %-10s %-6s %-6s\n",
           "ID", "Priorite", "Taille(Mo)", "Src", "Dst");
    afficher_separateur();
    Paquet* courant = f->tete;
    while (courant != NULL) {
        printf("  %-6d %-10d %-10.2f %-6d %-6d\n",
               courant->id, courant->priorite,
               courant->taille_Mo,
               courant->source, courant->destination);
        courant = courant->suivant;
    }
}

void liberer_file(FileAttente* f) {
    if (f == NULL) return;
    Paquet* courant = f->tete;
    while (courant != NULL) {
        Paquet* suivant = courant->suivant;
        free(courant);
        courant = suivant;
    }
    free(f);
}

/* =========================================================
 * PILE (LIFO) - Utilisee pour DFS et backtracking
 * ========================================================= */

Pile* creer_pile(void) {
    Pile* p = (Pile*)malloc(sizeof(Pile));
    VERIF_NULL(p, "creer_pile : allocation echouee");
    p->sommet = NULL;
    p->taille = 0;
    return p;
}

/** @complexity O(1) */
void empiler(Pile* p, int valeur) {
    NoeudPile* n = (NoeudPile*)malloc(sizeof(NoeudPile));
    VERIF_NULL(n, "empiler : allocation echouee");
    n->valeur  = valeur;
    n->suivant = p->sommet;
    p->sommet  = n;
    p->taille++;
}

/** @complexity O(1) */
int depiler(Pile* p) {
    if (pile_est_vide(p)) return -1;
    NoeudPile* n = p->sommet;
    int valeur   = n->valeur;
    p->sommet    = n->suivant;
    free(n);
    p->taille--;
    return valeur;
}

/** @complexity O(1) */
int sommet_pile(Pile* p) {
    if (pile_est_vide(p)) return -1;
    return p->sommet->valeur;
}

int pile_est_vide(Pile* p) {
    return (p == NULL || p->sommet == NULL);
}

void liberer_pile(Pile* p) {
    if (p == NULL) return;
    while (!pile_est_vide(p)) depiler(p);
    free(p);
}

/* =========================================================
 * FILE BFS (FIFO)
 * ========================================================= */

FileBFS* creer_file_bfs(void) {
    FileBFS* f = (FileBFS*)malloc(sizeof(FileBFS));
    VERIF_NULL(f, "creer_file_bfs : allocation echouee");
    f->tete   = NULL;
    f->queue  = NULL;
    f->taille = 0;
    return f;
}

/** @complexity O(1) - insertion en queue */
void enfiler_bfs(FileBFS* f, int valeur) {
    NoeudFile* n = (NoeudFile*)malloc(sizeof(NoeudFile));
    VERIF_NULL(n, "enfiler_bfs : allocation echouee");
    n->valeur  = valeur;
    n->suivant = NULL;
    if (f->queue != NULL) f->queue->suivant = n;
    else f->tete = n;
    f->queue = n;
    f->taille++;
}

/** @complexity O(1) - extraction en tete */
int defiler_bfs(FileBFS* f) {
    if (file_bfs_est_vide(f)) return -1;
    NoeudFile* n = f->tete;
    int valeur   = n->valeur;
    f->tete      = n->suivant;
    if (f->tete == NULL) f->queue = NULL;
    free(n);
    f->taille--;
    return valeur;
}

int file_bfs_est_vide(FileBFS* f) {
    return (f == NULL || f->tete == NULL);
}

void liberer_file_bfs(FileBFS* f) {
    if (f == NULL) return;
    while (!file_bfs_est_vide(f)) defiler_bfs(f);
    free(f);
}

/* =========================================================
 * CHEMIN - Liste chainee de noeuds de chemin
 * ========================================================= */

Chemin* creer_chemin(void) {
    Chemin* c = (Chemin*)malloc(sizeof(Chemin));
    VERIF_NULL(c, "creer_chemin : allocation echouee");
    c->noeuds             = NULL;
    c->latence_totale     = 0.0f;
    c->cout_total         = 0.0f;
    c->bande_passante_min = INFINI;
    c->longueur           = 0;
    return c;
}

/** @complexity O(n) - insertion en fin */
void ajouter_noeud_chemin(Chemin* c, int id_noeud) {
    NoeudChemin* n = (NoeudChemin*)malloc(sizeof(NoeudChemin));
    VERIF_NULL(n, "ajouter_noeud_chemin : allocation echouee");
    n->id_noeud = id_noeud;
    n->suivant  = NULL;

    if (c->noeuds == NULL) {
        c->noeuds = n;
    } else {
        NoeudChemin* courant = c->noeuds;
        while (courant->suivant != NULL) courant = courant->suivant;
        courant->suivant = n;
    }
    c->longueur++;
}

Chemin* copier_chemin(Chemin* c) {
    if (c == NULL) return NULL;
    Chemin* copie = creer_chemin();
    copie->latence_totale     = c->latence_totale;
    copie->cout_total         = c->cout_total;
    copie->bande_passante_min = c->bande_passante_min;
    NoeudChemin* courant = c->noeuds;
    while (courant != NULL) {
        ajouter_noeud_chemin(copie, courant->id_noeud);
        courant = courant->suivant;
    }
    return copie;
}

void afficher_chemin(Chemin* c) {
    if (c == NULL || c->noeuds == NULL) {
        afficher_avertissement("Aucun chemin a afficher.");
        return;
    }
    printf(COULEUR_VERT "  Chemin trouve :\n" COULEUR_RESET);
    printf("  Noeuds : ");
    NoeudChemin* courant = c->noeuds;
    while (courant != NULL) {
        printf("%d", courant->id_noeud);
        if (courant->suivant != NULL) printf(" -> ");
        courant = courant->suivant;
    }
    printf("\n");
    printf("  Latence totale     : %.2f ms\n", c->latence_totale);
    printf("  Cout total         : %.2f\n",    c->cout_total);
    printf("  Bande passante min : %.2f Mbps\n", c->bande_passante_min);
    printf("  Nombre de sauts    : %d\n", c->longueur - 1);
}

void liberer_chemin(Chemin* c) {
    if (c == NULL) return;
    NoeudChemin* courant = c->noeuds;
    while (courant != NULL) {
        NoeudChemin* suivant = courant->suivant;
        free(courant);
        courant = suivant;
    }
    free(c);
}

/* =========================================================
 * SIMULATION DE FLUX DE PAQUETS
 *
 * Simule l'arrivee et le traitement de nb_paquets paquets
 * avec une file de priorite de capacite donnee.
 *
 * Complexite : O(n * m) ou n = nb_paquets, m = capacite
 * ========================================================= */
StatistiquesFlux simuler_flux(int nb_paquets, int capacite, int nb_noeuds) {
    StatistiquesFlux stats = {0.0f, 0.0f, 0.0f, 0, 0, nb_paquets};
    FileAttente* file = creer_file(capacite);

    double temps_total_attente = 0.0;
    double debit_total = 0.0;
    srand((unsigned int)time(NULL));

    printf(COULEUR_BLEU
        "\n  Simulation de %d paquets (capacite file: %d)...\n"
        COULEUR_RESET, nb_paquets, capacite);

    for (int i = 0; i < nb_paquets; i++) {
        int   priorite = (rand() % 10) + 1;
        float taille   = ((float)(rand() % 100) / 10.0f) + 0.1f;
        int   src      = rand() % nb_noeuds;
        int   dst      = rand() % nb_noeuds;
        while (dst == src) dst = rand() % nb_noeuds;

        Paquet* p = creer_paquet(i, priorite, taille, src, dst);

        if (file_est_pleine(file)) {
            stats.paquets_perdus++;
            liberer_paquet(p);
        } else {
            enqueue(file, p);
        }

        /* Traiter quelques paquets periodiquement */
        if (i % 5 == 0 && !file_est_vide(file)) {
            Paquet* traite = dequeue(file);
            if (traite != NULL) {
                double attente = obtenir_temps_ms() - traite->temps_arrivee;
                temps_total_attente += attente;
                debit_total += traite->taille_Mo * 8.0; /* Conversion Mo -> Mb */
                stats.paquets_traites++;
                liberer_paquet(traite);
            }
        }
    }

    /* Vider la file restante */
    while (!file_est_vide(file)) {
        Paquet* traite = dequeue(file);
        if (traite != NULL) {
            double attente = obtenir_temps_ms() - traite->temps_arrivee;
            temps_total_attente += attente;
            debit_total += traite->taille_Mo * 8.0;
            stats.paquets_traites++;
            liberer_paquet(traite);
        }
    }

    liberer_file(file);

    /* Calcul des statistiques finales */
    if (stats.paquets_traites > 0) {
        stats.temps_moyen_attente = (float)(temps_total_attente / stats.paquets_traites);
        stats.debit_effectif      = (float)(debit_total / 1000.0); /* en Mbps */
    }
    stats.taux_perte = (nb_paquets > 0)
        ? (float)stats.paquets_perdus / nb_paquets * 100.0f
        : 0.0f;

    return stats;
}

void afficher_statistiques(StatistiquesFlux* stats) {
    if (stats == NULL) return;
    printf("\n");
    afficher_titre_section("STATISTIQUES DE FLUX");
    printf("  Paquets total        : %d\n",     stats->paquets_total);
    printf("  Paquets traites      : %d\n",     stats->paquets_traites);
    printf("  Paquets perdus       : %d\n",     stats->paquets_perdus);
    printf("  Temps moyen attente  : %.4f ms\n", stats->temps_moyen_attente);
    printf("  Taux de perte        : %.2f %%\n", stats->taux_perte);
    printf("  Debit effectif       : %.2f Mbps\n", stats->debit_effectif);
}
