/* =========================================================
 * securite.c - Module 3 : Detection d'Anomalies et Securite
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "securite.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================
 * DFS - Parcours en Profondeur
 * Complexite : O(V + E)
 * ========================================================= */

/**
 * @brief DFS iteratif utilisant la Pile implementee
 * Complexite : O(V + E)
 * Justification : Chaque sommet est empile/depile une fois,
 *                 chaque arete est examinee une fois.
 */
void dfs(Graphe* g, int depart, int* visite) {
    if (!noeud_valide(g, depart)) return;
    Pile* pile = creer_pile();
    empiler(pile, depart);

    while (!pile_est_vide(pile)) {
        int u = depiler(pile);
        if (visite[u]) continue;
        visite[u] = 1;

        Arete* a = g->noeuds[u].aretes;
        while (a != NULL) {
            if (!visite[a->destination])
                empiler(pile, a->destination);
            a = a->suivant;
        }
    }
    liberer_pile(pile);
}

void dfs_affichage(Graphe* g, int depart) {
    if (!noeud_valide(g, depart)) return;
    afficher_titre_section("PARCOURS DFS (Depth-First Search)");
    printf("  Depart : [%d] %s\n  Ordre de visite : ", depart, obtenir_nom_noeud(g, depart));

    int* visite = creer_tableau_int(g->nb_noeuds, 0);
    Pile* pile  = creer_pile();
    empiler(pile, depart);

    while (!pile_est_vide(pile)) {
        int u = depiler(pile);
        if (visite[u]) continue;
        visite[u] = 1;
        printf("[%d]%s ", u, obtenir_nom_noeud(g, u));

        Arete* a = g->noeuds[u].aretes;
        while (a != NULL) {
            if (!visite[a->destination])
                empiler(pile, a->destination);
            a = a->suivant;
        }
    }
    printf("\n");
    free(visite);
    liberer_pile(pile);
}

/**
 * @brief BFS iteratif utilisant la FileBFS implementee
 * Complexite : O(V + E)
 */
void bfs(Graphe* g, int depart, int* visite) {
    if (!noeud_valide(g, depart)) return;
    FileBFS* file = creer_file_bfs();
    visite[depart] = 1;
    enfiler_bfs(file, depart);

    while (!file_bfs_est_vide(file)) {
        int u = defiler_bfs(file);
        Arete* a = g->noeuds[u].aretes;
        while (a != NULL) {
            if (!visite[a->destination]) {
                visite[a->destination] = 1;
                enfiler_bfs(file, a->destination);
            }
            a = a->suivant;
        }
    }
    liberer_file_bfs(file);
}

void bfs_affichage(Graphe* g, int depart) {
    if (!noeud_valide(g, depart)) return;
    afficher_titre_section("PARCOURS BFS (Breadth-First Search)");
    printf("  Depart : [%d] %s\n  Ordre de visite : ", depart, obtenir_nom_noeud(g, depart));

    int* visite   = creer_tableau_int(g->nb_noeuds, 0);
    FileBFS* file = creer_file_bfs();
    visite[depart] = 1;
    enfiler_bfs(file, depart);

    while (!file_bfs_est_vide(file)) {
        int u = defiler_bfs(file);
        printf("[%d]%s ", u, obtenir_nom_noeud(g, u));
        Arete* a = g->noeuds[u].aretes;
        while (a != NULL) {
            if (!visite[a->destination]) {
                visite[a->destination] = 1;
                enfiler_bfs(file, a->destination);
            }
            a = a->suivant;
        }
    }
    printf("\n");
    free(visite);
    liberer_file_bfs(file);
}

/* =========================================================
 * DETECTION DE CYCLES
 * ========================================================= */

/**
 * @brief DFS avec coloration pour detecter les cycles
 * Couleurs : 0=blanc(non visite), 1=gris(en cours), 2=noir(termine)
 * @complexity O(V + E)
 */
int dfs_cycle(Graphe* g, int u, int* couleur) {
    couleur[u] = 1; /* Marquer gris : en cours de visite */

    Arete* a = g->noeuds[u].aretes;
    while (a != NULL) {
        int v = a->destination;
        if (couleur[v] == 1) {
            /* Arete vers un noeud gris = cycle detecte */
            printf(COULEUR_ROUGE
                "  [!] Cycle detecte : arete %d -> %d (%s -> %s)\n"
                COULEUR_RESET,
                u, v, obtenir_nom_noeud(g, u), obtenir_nom_noeud(g, v));
            return 1;
        }
        if (couleur[v] == 0 && dfs_cycle(g, v, couleur))
            return 1;
        a = a->suivant;
    }

    couleur[u] = 2; /* Marquer noir : visite termine */
    return 0;
}

int detecter_cycles(Graphe* g) {
    if (g == NULL) return 0;
    int* couleur = creer_tableau_int(g->nb_noeuds, 0);
    int cycle = 0;

    for (int i = 0; i < g->nb_noeuds && !cycle; i++) {
        if (couleur[i] == 0)
            cycle = dfs_cycle(g, i, couleur);
    }
    free(couleur);
    return cycle;
}

/* =========================================================
 * POINTS D'ARTICULATION
 * Algorithme de Tarjan-Hopcroft (DFS modifie)
 * Complexite : O(V + E)
 * ========================================================= */

void dfs_articulation(Graphe* g, int u, int parent,
                       int* disc, int* low, int* visite,
                       int* est_artic, int* timer) {
    visite[u] = 1;
    disc[u]   = low[u] = (*timer)++;
    int nb_enfants = 0;

    Arete* a = g->noeuds[u].aretes;
    while (a != NULL) {
        int v = a->destination;
        if (!visite[v]) {
            nb_enfants++;
            dfs_articulation(g, v, u, disc, low, visite, est_artic, timer);

            /* low[u] = min(low[u], low[v]) */
            if (low[v] < low[u]) low[u] = low[v];

            /* Condition 1 : racine DFS avec >= 2 enfants */
            if (parent == -1 && nb_enfants > 1) est_artic[u] = 1;

            /* Condition 2 : non-racine, low[v] >= disc[u] */
            if (parent != -1 && low[v] >= disc[u]) est_artic[u] = 1;
        } else if (v != parent) {
            /* Arete de retour : maj low[u] */
            if (disc[v] < low[u]) low[u] = disc[v];
        }
        a = a->suivant;
    }
}

void trouver_points_articulation(Graphe* g, int* points_artic, int* nb_points) {
    if (g == NULL) return;
    int V      = g->nb_noeuds;
    int* disc   = creer_tableau_int(V, -1);
    int* low    = creer_tableau_int(V, -1);
    int* visite = creer_tableau_int(V, 0);
    int* est_artic = creer_tableau_int(V, 0);
    int timer   = 0;
    *nb_points  = 0;

    for (int i = 0; i < V; i++) {
        if (!visite[i])
            dfs_articulation(g, i, -1, disc, low, visite, est_artic, &timer);
    }

    for (int i = 0; i < V; i++) {
        if (est_artic[i]) points_artic[(*nb_points)++] = i;
    }

    free(disc); free(low); free(visite); free(est_artic);
}

/* =========================================================
 * PONTS CRITIQUES
 * Complexite : O(V + E)
 * ========================================================= */

void dfs_ponts(Graphe* g, int u, int parent,
               int* disc, int* low, int* visite,
               int* p_src, int* p_dst, int* nb, int* timer) {
    visite[u] = 1;
    disc[u]   = low[u] = (*timer)++;

    Arete* a = g->noeuds[u].aretes;
    while (a != NULL) {
        int v = a->destination;
        if (!visite[v]) {
            dfs_ponts(g, v, u, disc, low, visite, p_src, p_dst, nb, timer);
            if (low[v] < low[u]) low[u] = low[v];

            /* Condition pont : low[v] > disc[u] */
            if (low[v] > disc[u]) {
                p_src[*nb] = u;
                p_dst[*nb] = v;
                (*nb)++;
            }
        } else if (v != parent) {
            if (disc[v] < low[u]) low[u] = disc[v];
        }
        a = a->suivant;
    }
}

void trouver_ponts(Graphe* g, int* ponts_src, int* ponts_dst, int* nb_ponts) {
    if (g == NULL) return;
    int V      = g->nb_noeuds;
    int* disc   = creer_tableau_int(V, -1);
    int* low    = creer_tableau_int(V, -1);
    int* visite = creer_tableau_int(V, 0);
    int timer   = 0;
    *nb_ponts   = 0;

    for (int i = 0; i < V; i++) {
        if (!visite[i])
            dfs_ponts(g, i, -1, disc, low, visite,
                      ponts_src, ponts_dst, nb_ponts, &timer);
    }
    free(disc); free(low); free(visite);
}

/* =========================================================
 * ALGORITHME DE KOSARAJU - Composantes Fortement Connexes
 * Complexite : O(V + E)
 * ========================================================= */

void dfs_kosaraju_passe1(Graphe* g, int u, int* visite, Pile* pile) {
    visite[u] = 1;
    Arete* a = g->noeuds[u].aretes;
    while (a != NULL) {
        if (!visite[a->destination])
            dfs_kosaraju_passe1(g, a->destination, visite, pile);
        a = a->suivant;
    }
    empiler(pile, u); /* Empiler apres visite complete */
}

void dfs_kosaraju_passe2(Graphe* g_t, int u, int* visite,
                          int scc_id, int* comp_id) {
    visite[u]  = 1;
    comp_id[u] = scc_id;
    Arete* a   = g_t->noeuds[u].aretes;
    while (a != NULL) {
        if (!visite[a->destination])
            dfs_kosaraju_passe2(g_t, a->destination, visite, scc_id, comp_id);
        a = a->suivant;
    }
}

Graphe* transposer_graphe(Graphe* g) {
    Graphe* gt = creer_graphe(g->nb_noeuds, 1);
    for (int i = 0; i < g->nb_noeuds; i++) {
        ajouter_noeud(gt, i, g->noeuds[i].nom);
        Arete* a = g->noeuds[i].aretes;
        while (a != NULL) {
            ajouter_arete(gt, a->destination, i,
                          a->latence, a->bande_passante,
                          a->cout, a->securite);
            a = a->suivant;
        }
    }
    return gt;
}

/**
 * @brief Kosaraju : trouve toutes les SCC en 2 passes DFS
 * @complexity O(V + E)
 */
int kosaraju(Graphe* g, int* composante_id) {
    if (g == NULL) return 0;
    int V      = g->nb_noeuds;
    int* visite = creer_tableau_int(V, 0);
    Pile* pile  = creer_pile();

    /* Passe 1 : DFS sur graphe original, empiler par fin de visite */
    for (int i = 0; i < V; i++) {
        if (!visite[i])
            dfs_kosaraju_passe1(g, i, visite, pile);
    }

    /* Transposer le graphe */
    Graphe* g_t = transposer_graphe(g);

    /* Passe 2 : DFS sur graphe transpose dans l'ordre inverse */
    for (int i = 0; i < V; i++) visite[i] = 0;
    int nb_scc = 0;

    while (!pile_est_vide(pile)) {
        int u = depiler(pile);
        if (!visite[u]) {
            dfs_kosaraju_passe2(g_t, u, visite, nb_scc, composante_id);
            nb_scc++;
        }
    }

    free(visite);
    liberer_pile(pile);
    detruire_graphe(g_t);
    return nb_scc;
}

/* =========================================================
 * RAPPORT DE SECURITE COMPLET
 * ========================================================= */

ResultatSecurite* analyser_securite_complete(Graphe* g) {
    if (g == NULL) return NULL;

    double temps_debut = obtenir_temps_ms();
    int V = g->nb_noeuds;

    ResultatSecurite* r = (ResultatSecurite*)malloc(sizeof(ResultatSecurite));
    VERIF_NULL(r, "analyser_securite_complete : allocation echouee");

    /* Initialiser */
    r->points_articulation   = creer_tableau_int(V, -1);
    r->ponts_src             = creer_tableau_int(V * V, -1);
    r->ponts_dst             = creer_tableau_int(V * V, -1);
    r->composante_id         = creer_tableau_int(V, -1);
    r->nb_points_articulation = 0;
    r->nb_ponts              = 0;
    r->nb_composantes        = 0;

    /* 1. Detection de cycles */
    r->a_des_cycles = detecter_cycles(g);
    r->nb_cycles_detectes = r->a_des_cycles ? 1 : 0;

    /* 2. Points d'articulation */
    trouver_points_articulation(g, r->points_articulation,
                                 &r->nb_points_articulation);

    /* 3. Ponts critiques */
    trouver_ponts(g, r->ponts_src, r->ponts_dst, &r->nb_ponts);

    /* 4. SCC par Kosaraju */
    r->nb_composantes = kosaraju(g, r->composante_id);

    /* 5. Connectivite */
    int* visite = creer_tableau_int(V, 0);
    dfs(g, 0, visite);
    r->est_connexe = 1;
    for (int i = 0; i < V; i++) {
        if (!visite[i]) { r->est_connexe = 0; break; }
    }
    free(visite);

    r->est_fortement_connexe = (r->nb_composantes == 1);
    r->temps_exec_ms = mesurer_temps(temps_debut, obtenir_temps_ms());
    return r;
}

void afficher_rapport_securite(ResultatSecurite* r, Graphe* g) {
    if (r == NULL) return;

    afficher_titre_section("RAPPORT DE SECURITE COMPLET");
    printf("  Temps d'analyse : %.3f ms\n\n", r->temps_exec_ms);

    /* Cycles */
    printf(COULEUR_JAUNE "  [1] CYCLES DE ROUTAGE\n" COULEUR_RESET);
    if (r->a_des_cycles)
        printf(COULEUR_ROUGE "    ALERTE : Cycles detectes dans le reseau !\n" COULEUR_RESET);
    else
        printf(COULEUR_VERT "    OK : Aucun cycle detecte.\n" COULEUR_RESET);

    /* Points d'articulation */
    printf(COULEUR_JAUNE "\n  [2] NOEUDS CRITIQUES (Points d'articulation)\n" COULEUR_RESET);
    if (r->nb_points_articulation == 0) {
        printf(COULEUR_VERT "    OK : Aucun noeud critique.\n" COULEUR_RESET);
    } else {
        printf(COULEUR_ROUGE "    ALERTE : %d noeud(s) critique(s) detecte(s) :\n" COULEUR_RESET,
               r->nb_points_articulation);
        for (int i = 0; i < r->nb_points_articulation; i++) {
            int id = r->points_articulation[i];
            printf("      - [%d] %s\n", id, obtenir_nom_noeud(g, id));
        }
    }

    /* Ponts */
    printf(COULEUR_JAUNE "\n  [3] ARETES CRITIQUES (Ponts)\n" COULEUR_RESET);
    if (r->nb_ponts == 0) {
        printf(COULEUR_VERT "    OK : Aucune arete critique.\n" COULEUR_RESET);
    } else {
        printf(COULEUR_ROUGE "    ALERTE : %d pont(s) critique(s) :\n" COULEUR_RESET,
               r->nb_ponts);
        for (int i = 0; i < r->nb_ponts; i++) {
            printf("      - %s --> %s\n",
                   obtenir_nom_noeud(g, r->ponts_src[i]),
                   obtenir_nom_noeud(g, r->ponts_dst[i]));
        }
    }

    /* SCC */
    printf(COULEUR_JAUNE "\n  [4] COMPOSANTES FORTEMENT CONNEXES (Kosaraju)\n" COULEUR_RESET);
    printf("    Nombre de SCC : %d\n", r->nb_composantes);
    if (r->est_fortement_connexe)
        printf(COULEUR_VERT "    OK : Reseau fortement connexe.\n" COULEUR_RESET);
    else {
        printf(COULEUR_ROUGE "    ALERTE : Reseau non fortement connexe (%d SCC)\n"
               COULEUR_RESET, r->nb_composantes);
        for (int scc = 0; scc < r->nb_composantes; scc++) {
            printf("      SCC #%d : ", scc);
            for (int i = 0; i < g->nb_noeuds; i++) {
                if (r->composante_id[i] == scc)
                    printf("[%d]%s ", i, obtenir_nom_noeud(g, i));
            }
            printf("\n");
        }
    }

    /* Connectivite generale */
    printf(COULEUR_JAUNE "\n  [5] CONNECTIVITE\n" COULEUR_RESET);
    printf("    Connexe            : %s\n",
           r->est_connexe ? COULEUR_VERT "OUI" COULEUR_RESET : COULEUR_ROUGE "NON" COULEUR_RESET);
    printf("    Fortement connexe  : %s\n",
           r->est_fortement_connexe ? COULEUR_VERT "OUI" COULEUR_RESET : COULEUR_ROUGE "NON" COULEUR_RESET);
}

void liberer_resultat_securite(ResultatSecurite* r) {
    if (r == NULL) return;
    free(r->points_articulation);
    free(r->ponts_src);
    free(r->ponts_dst);
    free(r->composante_id);
    free(r);
}
