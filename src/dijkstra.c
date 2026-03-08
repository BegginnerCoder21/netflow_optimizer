/* =========================================================
 * dijkstra.c - Module 2A : Algorithmes de Routage Optimal
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "dijkstra.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

/* =========================================================
 * FILE DE PRIORITE INTERNE (liste chainee triee)
 * Utilisee exclusivement par Dijkstra
 * ========================================================= */

FilePriorite* fp_creer(void) {
    FilePriorite* fp = (FilePriorite*)malloc(sizeof(FilePriorite));
    VERIF_NULL(fp, "fp_creer : allocation echouee");
    fp->tete   = NULL;
    fp->taille = 0;
    return fp;
}

/**
 * @brief Insere un noeud dans la file par distance croissante
 *
 * Complexite : O(n) - insertion triee dans liste chainee
 * Justification : Dans le pire cas, on parcourt toute la liste
 * pour trouver la bonne position d'insertion.
 */
void fp_inserer(FilePriorite* fp, int id, float dist) {
    NoeudFilePrio* n = (NoeudFilePrio*)malloc(sizeof(NoeudFilePrio));
    VERIF_NULL(n, "fp_inserer : allocation echouee");
    n->id_noeud = id;
    n->distance  = dist;
    n->suivant   = NULL;

    /* Insertion en tete si file vide ou distance minimale */
    if (fp->tete == NULL || dist < fp->tete->distance) {
        n->suivant = fp->tete;
        fp->tete   = n;
        fp->taille++;
        return;
    }

    /* Trouver la position d'insertion triee */
    NoeudFilePrio* courant = fp->tete;
    while (courant->suivant != NULL &&
           courant->suivant->distance <= dist) {
        courant = courant->suivant;
    }
    n->suivant       = courant->suivant;
    courant->suivant = n;
    fp->taille++;
}

/**
 * @brief Extrait le noeud de distance minimale (tete de liste triee)
 * @complexity O(1) - acces direct a la tete
 */
NoeudFilePrio* fp_extraire_min(FilePriorite* fp) {
    if (fp_est_vide(fp)) return NULL;
    NoeudFilePrio* min = fp->tete;
    fp->tete  = fp->tete->suivant;
    fp->taille--;
    min->suivant = NULL;
    return min;
}

/**
 * @brief Met a jour la distance d'un noeud deja dans la file
 * @complexity O(n) - recherche lineaire + reinsertion
 */
void fp_diminuer_cle(FilePriorite* fp, int id, float nouvelle_dist) {
    /* Supprimer l'ancienne entree */
    NoeudFilePrio* courant  = fp->tete;
    NoeudFilePrio* precedent = NULL;
    while (courant != NULL) {
        if (courant->id_noeud == id) {
            if (precedent == NULL) fp->tete = courant->suivant;
            else precedent->suivant = courant->suivant;
            fp->taille--;
            free(courant);
            break;
        }
        precedent = courant;
        courant   = courant->suivant;
    }
    /* Reinserer avec la nouvelle distance */
    fp_inserer(fp, id, nouvelle_dist);
}

int fp_est_vide(FilePriorite* fp) {
    return (fp == NULL || fp->tete == NULL);
}

void fp_liberer(FilePriorite* fp) {
    if (fp == NULL) return;
    NoeudFilePrio* courant = fp->tete;
    while (courant != NULL) {
        NoeudFilePrio* suivant = courant->suivant;
        free(courant);
        courant = suivant;
    }
    free(fp);
}

/* =========================================================
 * DIJKSTRA
 * ========================================================= */

/**
 * @brief Algorithme de Dijkstra avec file de priorite (liste chainee)
 *
 * =============================================================
 * PREUVE DE COMPLEXITE DETAILLEE
 * =============================================================
 * Notations : V = nombre de sommets, E = nombre d'aretes
 *
 * 1. Initialisation :
 *    - Allocation et init tableaux dist[], pred[], visite[] : O(V)
 *    - Insertion initiale dans la file                      : O(1)
 *
 * 2. Boucle principale (while !fp_est_vide) :
 *    - Chaque sommet est extrait exactement une fois        : V extractions
 *    - fp_extraire_min : O(1) avec liste chainee triee
 *    - Pour chaque sommet u extrait, on parcourt ses voisins : O(degre(u))
 *    - Somme des degres = E (pour graphe oriente)
 *    - fp_inserer ou fp_diminuer_cle : O(V) dans le pire cas
 *
 * 3. Total avec liste chainee :
 *    - V * O(V) pour les insertions = O(V^2)
 *    - Meilleur que matrice d'adjacence pour graphes creux
 *
 * Note : Avec un tas de Fibonacci, on obtient O((V+E) log V)
 *        Avec un tas binaire, on obtient O((V+E) log V)
 * =============================================================
 */
ResultatRoutage* dijkstra(Graphe* g, int source) {
    if (!noeud_valide(g, source)) return NULL;

    int V = g->nb_noeuds;
    double temps_debut = obtenir_temps_ms();

    /* --- Allocation du resultat --- */
    ResultatRoutage* r = (ResultatRoutage*)malloc(sizeof(ResultatRoutage));
    VERIF_NULL(r, "dijkstra : allocation resultat echouee");
    r->distances     = creer_tableau_float(V, INFINI);
    r->predecesseurs = creer_tableau_int(V, -1);
    r->nb_noeuds     = V;
    r->source        = source;
    strncpy(r->nom_algo, "Dijkstra", 49);

    int* visite = creer_tableau_int(V, 0);

    /* Distance source -> source = 0 */
    r->distances[source] = 0.0f;

    /* File de priorite initialisee avec le noeud source */
    FilePriorite* fp = fp_creer();
    fp_inserer(fp, source, 0.0f);

    /* --- Boucle principale --- */
    while (!fp_est_vide(fp)) {
        /* Extraire le noeud non-visite de distance minimale - O(1) */
        NoeudFilePrio* min_noeud = fp_extraire_min(fp);
        int u = min_noeud->id_noeud;
        free(min_noeud);

        if (visite[u]) continue;
        visite[u] = 1;

        /* Relaxer toutes les aretes sortantes de u - O(degre(u)) */
        Arete* a = g->noeuds[u].aretes;
        while (a != NULL) {
            int   v         = a->destination;
            float poids_uv  = a->latence; /* On optimise sur la latence */
            float dist_via_u = r->distances[u] + poids_uv;

            if (!visite[v] && dist_via_u < r->distances[v]) {
                r->distances[v]     = dist_via_u;
                r->predecesseurs[v] = u;
                /* Inserer (ou reinsertion) dans la file - O(V) */
                fp_inserer(fp, v, dist_via_u);
            }
            a = a->suivant;
        }
    }

    fp_liberer(fp);
    free(visite);

    r->temps_exec_ms = mesurer_temps(temps_debut, obtenir_temps_ms());
    return r;
}

/**
 * @brief Reconstruit le chemin optimal depuis predecesseurs[]
 *
 * Utilise la pile (LIFO) pour inverser le chemin reconstruit.
 * @complexity O(V) - parcours des predecesseurs
 */
Chemin* reconstruire_chemin(ResultatRoutage* r, int dest, Graphe* g) {
    if (r == NULL || !noeud_valide(g, dest)) return NULL;
    if (r->distances[dest] >= INFINI) {
        afficher_avertissement("Destination inaccessible depuis la source.");
        return NULL;
    }

    /* Remonter les predecesseurs avec une pile pour inverser - O(V) */
    Pile* pile = creer_pile();
    int courant = dest;
    while (courant != -1) {
        empiler(pile, courant);
        courant = r->predecesseurs[courant];
    }

    /* Construire le chemin en depilant */
    Chemin* c = creer_chemin();
    c->latence_totale     = r->distances[dest];
    c->bande_passante_min = INFINI;
    c->cout_total         = 0.0f;

    int precedent = -1;
    while (!pile_est_vide(pile)) {
        int noeud = depiler(pile);
        ajouter_noeud_chemin(c, noeud);
        if (precedent != -1) {
            Arete* a = obtenir_arete(g, precedent, noeud);
            if (a != NULL) {
                c->cout_total += a->cout;
                if (a->bande_passante < c->bande_passante_min)
                    c->bande_passante_min = a->bande_passante;
            }
        }
        precedent = noeud;
    }
    liberer_pile(pile);
    return c;
}

/* =========================================================
 * BELLMAN-FORD
 * ========================================================= */

/**
 * @brief Algorithme de Bellman-Ford
 *
 * =============================================================
 * PREUVE DE COMPLEXITE DETAILLEE
 * =============================================================
 * Principe : Relaxation de toutes les aretes, V-1 fois.
 *
 * 1. Initialisation : O(V)
 *
 * 2. Boucle principale : V-1 iterations
 *    - Chaque iteration parcourt toutes les aretes : O(E)
 *    - Total boucle principale : O(V * E) = O(VE)
 *
 * 3. Detection de cycle negatif : O(E)
 *    - Une V-ieme relaxation possible => cycle negatif
 *
 * 4. Total : O(VE)
 *
 * Comparaison Dijkstra vs Bellman-Ford :
 * +------------------+----------------+--------------+
 * | Critere          | Dijkstra       | Bellman-Ford |
 * +------------------+----------------+--------------+
 * | Complexite       | O(V^2) ou      | O(VE)        |
 * |                  | O((V+E)log V)  |              |
 * | Poids negatifs   | Non            | Oui          |
 * | Cycles negatifs  | Non detectes   | Detectes     |
 * | Efficacite       | Meilleur cas   | Universel    |
 * +------------------+----------------+--------------+
 * =============================================================
 */
ResultatRoutage* bellman_ford(Graphe* g, int source) {
    if (!noeud_valide(g, source)) return NULL;

    int V = g->nb_noeuds;
    double temps_debut = obtenir_temps_ms();

    ResultatRoutage* r = (ResultatRoutage*)malloc(sizeof(ResultatRoutage));
    VERIF_NULL(r, "bellman_ford : allocation echouee");
    r->distances     = creer_tableau_float(V, INFINI);
    r->predecesseurs = creer_tableau_int(V, -1);
    r->nb_noeuds     = V;
    r->source        = source;
    strncpy(r->nom_algo, "Bellman-Ford", 49);

    r->distances[source] = 0.0f;

    /* --- V-1 iterations de relaxation --- */
    for (int iter = 0; iter < V - 1; iter++) {
        int modifie = 0;

        /* Parcourir TOUTES les aretes - O(E) */
        for (int u = 0; u < V; u++) {
            if (r->distances[u] >= INFINI) continue; /* Noeud inaccessible */
            Arete* a = g->noeuds[u].aretes;
            while (a != NULL) {
                int   v        = a->destination;
                float nouveau  = r->distances[u] + a->latence;
                if (nouveau < r->distances[v]) {
                    r->distances[v]     = nouveau;
                    r->predecesseurs[v] = u;
                    modifie = 1;
                }
                a = a->suivant;
            }
        }
        if (!modifie) break; /* Convergence anticipee */
    }

    /* --- Detection de cycle negatif (V-ieme iteration) --- */
    for (int u = 0; u < V; u++) {
        Arete* a = g->noeuds[u].aretes;
        while (a != NULL) {
            if (r->distances[u] < INFINI &&
                r->distances[u] + a->latence < r->distances[a->destination]) {
                afficher_avertissement(
                    "Bellman-Ford : Cycle de poids negatif detecte !");
                liberer_resultat_routage(r);
                return NULL;
            }
            a = a->suivant;
        }
    }

    r->temps_exec_ms = mesurer_temps(temps_debut, obtenir_temps_ms());
    return r;
}

/* =========================================================
 * Affichage et Comparaison
 * ========================================================= */

void afficher_tous_chemins(ResultatRoutage* r, Graphe* g) {
    if (r == NULL) return;
    afficher_titre_section("TOUS LES PLUS COURTS CHEMINS");
    printf("  Algorithme : %s | Source : [%d] %s | Temps : %.3f ms\n\n",
           r->nom_algo, r->source,
           obtenir_nom_noeud(g, r->source),
           r->temps_exec_ms);

    for (int i = 0; i < r->nb_noeuds; i++) {
        if (i == r->source) continue;
        printf("  [%d] %-20s : ", i, obtenir_nom_noeud(g, i));
        if (r->distances[i] >= INFINI) {
            printf(COULEUR_ROUGE "INACCESSIBLE\n" COULEUR_RESET);
        } else {
            printf(COULEUR_VERT "%.2f ms" COULEUR_RESET, r->distances[i]);
            /* Afficher le chemin en remontant */
            int chemin_ids[TAILLE_MAX_NOEUDS];
            int len = 0;
            int courant = i;
            while (courant != -1 && len < TAILLE_MAX_NOEUDS) {
                chemin_ids[len++] = courant;
                courant = r->predecesseurs[courant];
            }
            printf("  (");
            for (int j = len - 1; j >= 0; j--) {
                printf("%d", chemin_ids[j]);
                if (j > 0) printf("->");
            }
            printf(")\n");
        }
    }
}

void afficher_chemin_detail(ResultatRoutage* r, int dest, Graphe* g) {
    if (r == NULL || !noeud_valide(g, dest)) return;
    Chemin* c = reconstruire_chemin(r, dest, g);
    if (c != NULL) {
        printf("\n  Source : [%d] %s\n",
               r->source, obtenir_nom_noeud(g, r->source));
        printf("  Dest   : [%d] %s\n",
               dest, obtenir_nom_noeud(g, dest));
        afficher_chemin(c);
        liberer_chemin(c);
    }
}

/**
 * @brief Compare Dijkstra et Bellman-Ford sur le meme graphe
 * Affiche distances, temps, et identifie les differences
 */
void comparer_dijkstra_bellman(Graphe* g, int source) {
    afficher_titre_section("COMPARAISON : Dijkstra vs Bellman-Ford");

    ResultatRoutage* r_dijk = dijkstra(g, source);
    ResultatRoutage* r_bell = bellman_ford(g, source);

    if (r_dijk == NULL || r_bell == NULL) {
        afficher_erreur("Echec d'un des algorithmes");
        liberer_resultat_routage(r_dijk);
        liberer_resultat_routage(r_bell);
        return;
    }

    printf("\n  %-20s | %-12s | %-12s | %s\n",
           "Destination", "Dijkstra(ms)", "Bellman(ms)", "Egal?");
    afficher_separateur();

    int differences = 0;
    for (int i = 0; i < g->nb_noeuds; i++) {
        if (i == source) continue;
        float d1 = r_dijk->distances[i];
        float d2 = r_bell->distances[i];
        int egal = (d1 >= INFINI && d2 >= INFINI) ||
                   (d1 < INFINI && d2 < INFINI && (d1 - d2 < 0.001f && d2 - d1 < 0.001f));
        if (!egal) differences++;
        printf("  %-20s | %-12.2f | %-12.2f | %s\n",
               obtenir_nom_noeud(g, i),
               d1 >= INFINI ? -1.0f : d1,
               d2 >= INFINI ? -1.0f : d2,
               egal ? COULEUR_VERT "OUI" COULEUR_RESET : COULEUR_ROUGE "NON" COULEUR_RESET);
    }

    printf("\n");
    afficher_benchmark("Dijkstra",     g->nb_noeuds, r_dijk->temps_exec_ms);
    afficher_benchmark("Bellman-Ford", g->nb_noeuds, r_bell->temps_exec_ms);
    printf("\n  Differences detectees : %d\n", differences);
    if (differences == 0)
        afficher_succes("Les deux algorithmes donnent les memes resultats.");

    liberer_resultat_routage(r_dijk);
    liberer_resultat_routage(r_bell);
}

void liberer_resultat_routage(ResultatRoutage* r) {
    if (r == NULL) return;
    if (r->distances)     free(r->distances);
    if (r->predecesseurs) free(r->predecesseurs);
    free(r);
}
