/* =========================================================
 * graphe.c - Module 1 : Modelisation du Reseau
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "graphe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================
 * Creation et destruction
 * ========================================================= */

/**
 * @brief Cree un graphe avec V noeuds et matrice V x V
 * @complexity O(V^2) pour allocation et initialisation matrice
 */
Graphe* creer_graphe(int nb_noeuds, int est_oriente) {
    Graphe* g = (Graphe*)malloc(sizeof(Graphe));
    VERIF_NULL(g, "creer_graphe : allocation graphe echouee");

    g->nb_noeuds  = nb_noeuds;
    g->nb_aretes  = 0;
    g->capacite   = nb_noeuds;
    g->est_oriente = est_oriente;

    /* Allocation du tableau de noeuds - O(V) */
    g->noeuds = (Noeud*)calloc(nb_noeuds, sizeof(Noeud));
    VERIF_NULL(g->noeuds, "creer_graphe : allocation noeuds echouee");

    /* Initialisation des noeuds */
    for (int i = 0; i < nb_noeuds; i++) {
        g->noeuds[i].id           = i;
        g->noeuds[i].aretes       = NULL;
        g->noeuds[i].degre_sortie = 0;
        g->noeuds[i].degre_entree = 0;
        snprintf(g->noeuds[i].nom, TAILLE_MAX_NOM, "Noeud_%d", i);
    }

    /* Allocation de la matrice d'adjacence - O(V^2) */
    g->matrice_adjacence = (float**)malloc(nb_noeuds * sizeof(float*));
    VERIF_NULL(g->matrice_adjacence, "creer_graphe : allocation matrice echouee");

    for (int i = 0; i < nb_noeuds; i++) {
        g->matrice_adjacence[i] = (float*)malloc(nb_noeuds * sizeof(float));
        VERIF_NULL(g->matrice_adjacence[i], "creer_graphe : allocation ligne matrice echouee");
        for (int j = 0; j < nb_noeuds; j++) {
            g->matrice_adjacence[i][j] = (i == j) ? 0.0f : INFINI;
        }
    }

    return g;
}

/**
 * @brief Libere toute la memoire du graphe
 * @complexity O(V + E) - parcours de toutes les listes
 */
void detruire_graphe(Graphe* g) {
    if (g == NULL) return;

    /* Liberer les listes d'adjacence - O(V + E) */
    for (int i = 0; i < g->nb_noeuds; i++) {
        Arete* courant = g->noeuds[i].aretes;
        while (courant != NULL) {
            Arete* suivant = courant->suivant;
            free(courant);
            courant = suivant;
        }
    }
    free(g->noeuds);

    /* Liberer la matrice - O(V) */
    for (int i = 0; i < g->capacite; i++) {
        free(g->matrice_adjacence[i]);
    }
    free(g->matrice_adjacence);

    free(g);
}

/* =========================================================
 * Modification du graphe
 * ========================================================= */

/**
 * @complexity O(1)
 */
void ajouter_noeud(Graphe* g, int id, const char* nom) {
    if (g == NULL || id < 0 || id >= g->capacite) return;
    g->noeuds[id].id = id;
    strncpy(g->noeuds[id].nom, nom, TAILLE_MAX_NOM - 1);
    g->noeuds[id].nom[TAILLE_MAX_NOM - 1] = '\0';
}

/**
 * @brief Ajoute une arete dans la liste d'adjacence et dans la matrice
 *
 * Analyse de complexite :
 *   - Insertion en tete de liste : O(1)
 *   - Mise a jour matrice        : O(1)
 *   - Total                      : O(1)
 */
void ajouter_arete(Graphe* g, int src, int dest,
                   float latence, float bande_passante,
                   float cout, int securite) {
    if (g == NULL || !noeud_valide(g, src) || !noeud_valide(g, dest)) return;

    /* Creer le nouveau maillon */
    Arete* a = (Arete*)malloc(sizeof(Arete));
    VERIF_NULL(a, "ajouter_arete : allocation echouee");
    a->destination    = dest;
    a->latence        = latence;
    a->bande_passante = bande_passante;
    a->cout           = cout;
    a->securite       = securite;

    /* Insertion en tete de la liste d'adjacence - O(1) */
    a->suivant              = g->noeuds[src].aretes;
    g->noeuds[src].aretes   = a;
    g->noeuds[src].degre_sortie++;
    g->noeuds[dest].degre_entree++;

    /* Mise a jour de la matrice avec la latence - O(1) */
    g->matrice_adjacence[src][dest] = latence;

    g->nb_aretes++;

    /* Si non-oriente : ajouter l'arete inverse */
    if (!g->est_oriente) {
        Arete* b = (Arete*)malloc(sizeof(Arete));
        VERIF_NULL(b, "ajouter_arete : allocation inverse echouee");
        b->destination    = src;
        b->latence        = latence;
        b->bande_passante = bande_passante;
        b->cout           = cout;
        b->securite       = securite;
        b->suivant              = g->noeuds[dest].aretes;
        g->noeuds[dest].aretes  = b;
        g->noeuds[dest].degre_sortie++;
        g->noeuds[src].degre_entree++;
        g->matrice_adjacence[dest][src] = latence;
        g->nb_aretes++;
    }
}

/**
 * @complexity O(degre(src)) pour trouver et supprimer l'arete
 */
void supprimer_arete(Graphe* g, int src, int dest) {
    if (g == NULL || !noeud_valide(g, src) || !noeud_valide(g, dest)) return;

    Arete* courant  = g->noeuds[src].aretes;
    Arete* precedent = NULL;

    while (courant != NULL) {
        if (courant->destination == dest) {
            if (precedent == NULL) g->noeuds[src].aretes = courant->suivant;
            else precedent->suivant = courant->suivant;
            free(courant);
            g->noeuds[src].degre_sortie--;
            g->noeuds[dest].degre_entree--;
            g->matrice_adjacence[src][dest] = INFINI;
            g->nb_aretes--;
            return;
        }
        precedent = courant;
        courant   = courant->suivant;
    }
}

/**
 * @complexity O(V + E) - suppression de toutes les aretes liees
 */
void supprimer_noeud(Graphe* g, int id) {
    if (g == NULL || !noeud_valide(g, id)) return;

    /* Supprimer toutes les aretes sortantes */
    Arete* courant = g->noeuds[id].aretes;
    while (courant != NULL) {
        Arete* suivant = courant->suivant;
        free(courant);
        courant = suivant;
    }
    g->noeuds[id].aretes = NULL;

    /* Supprimer toutes les aretes entrantes depuis les autres noeuds */
    for (int i = 0; i < g->nb_noeuds; i++) {
        if (i != id) supprimer_arete(g, i, id);
    }

    /* Reinitialiser la ligne et la colonne dans la matrice */
    for (int j = 0; j < g->nb_noeuds; j++) {
        g->matrice_adjacence[id][j] = INFINI;
        g->matrice_adjacence[j][id] = INFINI;
    }
    g->matrice_adjacence[id][id] = 0.0f;
}

/* =========================================================
 * Persistance - Chargement depuis fichier
 * ========================================================= */

/**
 * @brief Parse et charge un graphe depuis un fichier texte
 *
 * Format attendu :
 *   # commentaire (lignes ignorees)
 *   ORIENTE 1          (optionnel, defaut=1)
 *   NOEUDS <n>
 *   <id> <nom>
 *   ARETES <m>
 *   <src> <dst> <latence> <bp> <cout> <securite>
 *
 * @complexity O(V^2 + E) - creation graphe + lecture aretes
 */
Graphe* charger_graphe_fichier(const char* chemin) {
    FILE* f = fopen(chemin, "r");
    if (f == NULL) {
        fprintf(stderr, COULEUR_ROUGE
            "[ERREUR] Impossible d'ouvrir : %s\n" COULEUR_RESET, chemin);
        return NULL;
    }

    char  ligne[TAILLE_MAX_BUFFER];
    int   nb_noeuds  = 0;
    int   est_oriente = 1;
    Graphe* g = NULL;

    while (fgets(ligne, sizeof(ligne), f)) {
        /* Ignorer commentaires et lignes vides */
        if (ligne[0] == '#' || ligne[0] == '\n' || ligne[0] == '\r') continue;

        if (strncmp(ligne, "ORIENTE", 7) == 0) {
            sscanf(ligne, "ORIENTE %d", &est_oriente);
        }
        else if (strncmp(ligne, "NOEUDS", 6) == 0) {
            sscanf(ligne, "NOEUDS %d", &nb_noeuds);
            g = creer_graphe(nb_noeuds, est_oriente);

            /* Lire les noeuds */
            for (int i = 0; i < nb_noeuds; i++) {
                if (!fgets(ligne, sizeof(ligne), f)) break;
                if (ligne[0] == '#' || ligne[0] == '\n') { i--; continue; }
                int  id;
                char nom[TAILLE_MAX_NOM];
                if (sscanf(ligne, "%d %49s", &id, nom) == 2) {
                    ajouter_noeud(g, id, nom);
                }
            }
        }
        else if (strncmp(ligne, "ARETES", 6) == 0) {
            int nb_aretes = 0;
            sscanf(ligne, "ARETES %d", &nb_aretes);

            for (int i = 0; i < nb_aretes; i++) {
                if (!fgets(ligne, sizeof(ligne), f)) break;
                if (ligne[0] == '#' || ligne[0] == '\n') { i--; continue; }
                int   src, dest, securite;
                float latence, bp, cout;
                if (sscanf(ligne, "%d %d %f %f %f %d",
                           &src, &dest, &latence, &bp, &cout, &securite) == 6) {
                    if (g != NULL) ajouter_arete(g, src, dest, latence, bp, cout, securite);
                }
            }
        }
    }

    fclose(f);
    if (g != NULL) {
        printf(COULEUR_VERT
            "  [OK] Graphe charge : %d noeuds, %d aretes depuis '%s'\n"
            COULEUR_RESET, g->nb_noeuds, g->nb_aretes, chemin);
    }
    return g;
}

/**
 * @complexity O(V + E)
 */
void sauvegarder_graphe(Graphe* g, const char* chemin) {
    if (g == NULL) return;
    FILE* f = fopen(chemin, "w");
    if (f == NULL) {
        afficher_erreur("Impossible de creer le fichier de sauvegarde");
        return;
    }

    fprintf(f, "# Graphe sauvegarde par NetFlow Optimizer\n");
    fprintf(f, "# Format : NOEUDS n / id nom / ARETES m / src dst lat bp cout sec\n");
    fprintf(f, "ORIENTE %d\n", g->est_oriente);
    fprintf(f, "NOEUDS %d\n", g->nb_noeuds);
    for (int i = 0; i < g->nb_noeuds; i++) {
        fprintf(f, "%d %s\n", g->noeuds[i].id, g->noeuds[i].nom);
    }

    /* Compter les aretes reelles (non-orientees : eviter doublons) */
    int nb_a = g->est_oriente ? g->nb_aretes : g->nb_aretes / 2;
    fprintf(f, "ARETES %d\n", nb_a);
    for (int i = 0; i < g->nb_noeuds; i++) {
        Arete* courant = g->noeuds[i].aretes;
        while (courant != NULL) {
            /* Pour non-oriente, n'ecrire que src < dest */
            if (g->est_oriente || i < courant->destination) {
                fprintf(f, "%d %d %.2f %.2f %.2f %d\n",
                        i, courant->destination,
                        courant->latence, courant->bande_passante,
                        courant->cout, courant->securite);
            }
            courant = courant->suivant;
        }
    }
    fclose(f);
    printf(COULEUR_VERT "  [OK] Graphe sauvegarde dans '%s'\n" COULEUR_RESET, chemin);
}

/* =========================================================
 * Affichage
 * ========================================================= */

void afficher_graphe(Graphe* g) {
    if (g == NULL) { afficher_erreur("Graphe NULL"); return; }

    afficher_titre_section("GRAPHE - Liste d'adjacence");
    printf("  Noeuds : %d | Aretes : %d | %s\n",
           g->nb_noeuds, g->nb_aretes,
           g->est_oriente ? "Oriente" : "Non-oriente");
    afficher_separateur();

    for (int i = 0; i < g->nb_noeuds; i++) {
        printf(COULEUR_CYAN "  [%d] %s" COULEUR_RESET " (degre_out=%d) -->",
               g->noeuds[i].id, g->noeuds[i].nom,
               g->noeuds[i].degre_sortie);

        Arete* a = g->noeuds[i].aretes;
        if (a == NULL) {
            printf(" (aucune arete)\n");
        } else {
            printf("\n");
            while (a != NULL) {
                printf("      --> [%d] %s | lat=%.1fms bp=%.1fMbps cout=%.1f sec=%d\n",
                       a->destination,
                       g->noeuds[a->destination].nom,
                       a->latence, a->bande_passante,
                       a->cout, a->securite);
                a = a->suivant;
            }
        }
    }
}

void afficher_matrice(Graphe* g) {
    if (g == NULL) return;

    afficher_titre_section("GRAPHE - Matrice d'adjacence (latences en ms)");
    int n = g->nb_noeuds;

    /* En-tete colonne */
    printf("       ");
    for (int j = 0; j < n; j++) printf(" %6d", j);
    printf("\n");
    afficher_separateur();

    for (int i = 0; i < n; i++) {
        printf("  [%2d] ", i);
        for (int j = 0; j < n; j++) {
            if (g->matrice_adjacence[i][j] >= INFINI)
                printf("    INF");
            else
                printf(" %6.1f", g->matrice_adjacence[i][j]);
        }
        printf("\n");
    }
}

void afficher_noeud(Graphe* g, int id) {
    if (!noeud_valide(g, id)) return;
    Noeud* n = &g->noeuds[id];
    printf("  Noeud [%d] : %s | degre_out=%d | degre_in=%d\n",
           n->id, n->nom, n->degre_sortie, n->degre_entree);
}

/* =========================================================
 * Utilitaires
 * ========================================================= */

int noeud_valide(Graphe* g, int id) {
    return (g != NULL && id >= 0 && id < g->nb_noeuds);
}

int arete_existe(Graphe* g, int src, int dest) {
    return (obtenir_arete(g, src, dest) != NULL);
}

/**
 * @complexity O(degre(src))
 */
Arete* obtenir_arete(Graphe* g, int src, int dest) {
    if (!noeud_valide(g, src) || !noeud_valide(g, dest)) return NULL;
    Arete* courant = g->noeuds[src].aretes;
    while (courant != NULL) {
        if (courant->destination == dest) return courant;
        courant = courant->suivant;
    }
    return NULL;
}

const char* obtenir_nom_noeud(Graphe* g, int id) {
    if (!noeud_valide(g, id)) return "?";
    return g->noeuds[id].nom;
}

void mettre_a_jour_matrice(Graphe* g) {
    if (g == NULL) return;
    /* Reinitialiser */
    for (int i = 0; i < g->nb_noeuds; i++)
        for (int j = 0; j < g->nb_noeuds; j++)
            g->matrice_adjacence[i][j] = (i == j) ? 0.0f : INFINI;

    /* Remplir depuis les listes - O(V + E) */
    for (int i = 0; i < g->nb_noeuds; i++) {
        Arete* a = g->noeuds[i].aretes;
        while (a != NULL) {
            g->matrice_adjacence[i][a->destination] = a->latence;
            a = a->suivant;
        }
    }
}

/**
 * @brief Genere un graphe connexe aleatoire
 * @complexity O(V^2) dans le pire cas
 */
Graphe* generer_graphe_aleatoire(int nb_noeuds, float densite, int est_oriente) {
    Graphe* g = creer_graphe(nb_noeuds, est_oriente);
    srand((unsigned int)time(NULL));

    char nom[TAILLE_MAX_NOM];
    const char* prefixes[] = {"Routeur", "Switch", "Serveur", "Hub", "Passerelle"};

    for (int i = 0; i < nb_noeuds; i++) {
        snprintf(nom, TAILLE_MAX_NOM, "%s_%d",
                 prefixes[i % 5], i);
        ajouter_noeud(g, i, nom);
    }

    /* Assurer la connexite : arbre couvrant d'abord */
    for (int i = 1; i < nb_noeuds; i++) {
        int src  = rand() % i;
        float lat = (float)(rand() % 100 + 1);
        float bp  = (float)(rand() % 1000 + 10);
        float cout = (float)(rand() % 50 + 1);
        int   sec = rand() % 11;
        ajouter_arete(g, src, i, lat, bp, cout, sec);
    }

    /* Ajouter des aretes supplementaires selon la densite */
    for (int i = 0; i < nb_noeuds; i++) {
        for (int j = 0; j < nb_noeuds; j++) {
            if (i == j) continue;
            if ((float)rand() / RAND_MAX < densite) {
                if (!arete_existe(g, i, j)) {
                    float lat  = (float)(rand() % 100 + 1);
                    float bp   = (float)(rand() % 1000 + 10);
                    float cout = (float)(rand() % 50 + 1);
                    int   sec  = rand() % 11;
                    ajouter_arete(g, i, j, lat, bp, cout, sec);
                }
            }
        }
    }

    printf(COULEUR_VERT
        "  [OK] Graphe aleatoire genere : %d noeuds, %d aretes\n"
        COULEUR_RESET, g->nb_noeuds, g->nb_aretes);
    return g;
}
