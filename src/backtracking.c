/* =========================================================
 * backtracking.c - Module 2B : Chemins Contraints
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "backtracking.h"
#include "dijkstra.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================
 * CONTRAINTES
 * ========================================================= */

Contraintes* creer_contraintes(float bp_min, float cout_max, int sec_min) {
    Contraintes* c = (Contraintes*)malloc(sizeof(Contraintes));
    VERIF_NULL(c, "creer_contraintes : allocation echouee");
    c->bande_passante_min = bp_min;
    c->cout_max           = cout_max;
    c->securite_min       = sec_min;
    c->noeuds_oblg        = NULL;
    c->nb_noeuds_oblg     = 0;
    c->noeuds_exclus      = NULL;
    c->nb_noeuds_exclus   = 0;
    c->optimiser_latence  = 1;
    return c;
}

void ajouter_noeud_oblg(Contraintes* c, int id) {
    c->noeuds_oblg = (int*)realloc(c->noeuds_oblg,
        (c->nb_noeuds_oblg + 1) * sizeof(int));
    VERIF_NULL(c->noeuds_oblg, "ajouter_noeud_oblg : realloc echoue");
    c->noeuds_oblg[c->nb_noeuds_oblg++] = id;
}

void ajouter_noeud_exclu(Contraintes* c, int id) {
    c->noeuds_exclus = (int*)realloc(c->noeuds_exclus,
        (c->nb_noeuds_exclus + 1) * sizeof(int));
    VERIF_NULL(c->noeuds_exclus, "ajouter_noeud_exclu : realloc echoue");
    c->noeuds_exclus[c->nb_noeuds_exclus++] = id;
}

void afficher_contraintes(Contraintes* c) {
    if (c == NULL) { printf("  Aucune contrainte.\n"); return; }
    printf("  Contraintes :\n");
    printf("    BP minimum     : %.1f Mbps\n", c->bande_passante_min);
    printf("    Cout maximum   : %.1f\n",       c->cout_max);
    printf("    Securite min   : %d/10\n",       c->securite_min);
    printf("    Noeuds oblg    : ");
    for (int i = 0; i < c->nb_noeuds_oblg; i++)
        printf("%d ", c->noeuds_oblg[i]);
    printf("\n");
    printf("    Noeuds exclus  : ");
    for (int i = 0; i < c->nb_noeuds_exclus; i++)
        printf("%d ", c->noeuds_exclus[i]);
    printf("\n");
}

void liberer_contraintes(Contraintes* c) {
    if (c == NULL) return;
    if (c->noeuds_oblg)  free(c->noeuds_oblg);
    if (c->noeuds_exclus) free(c->noeuds_exclus);
    free(c);
}

/* =========================================================
 * BACKTRACKING - Fonctions internes
 * ========================================================= */

/**
 * @brief Verifie si le chemin courant satisfait TOUTES les contraintes
 */
int contraintes_satisfaites(ContexteBacktrack* ctx, int dest) {
    /* 1. On doit etre arrive a la destination */
    if (ctx->chemin_courant[ctx->longueur_courante - 1] != dest) return 0;

    /* 2. Tous les noeuds obligatoires doivent etre visites */
    if (ctx->contraintes != NULL) {
        for (int i = 0; i < ctx->contraintes->nb_noeuds_oblg; i++) {
            int oblg = ctx->contraintes->noeuds_oblg[i];
            if (!contient(ctx->chemin_courant, ctx->longueur_courante, oblg))
                return 0;
        }
    }
    return 1;
}

/**
 * @brief Elagage precoce : peut-on continuer depuis ce noeud ?
 *
 * Retourne 0 (couper la branche) si :
 *   - Noeud deja visite (evite les cycles)
 *   - Noeud dans la liste des exclus
 *   - Cout accumule depasse le maximum
 *   - Securite de l'arete insuffisante
 */
static int peut_visiter(ContexteBacktrack* ctx, int noeud_suivant, Arete* arete) {
    /* 1. Cycle : noeud deja visite */
    if (ctx->visite[noeud_suivant]) return 0;

    /* 2. Noeud exclu explicitement */
    if (ctx->contraintes != NULL &&
        contient(ctx->contraintes->noeuds_exclus,
                 ctx->contraintes->nb_noeuds_exclus,
                 noeud_suivant)) return 0;

    /* 3. Bande passante insuffisante sur cette arete */
    if (ctx->contraintes != NULL &&
        arete->bande_passante < ctx->contraintes->bande_passante_min) return 0;

    /* 4. Securite insuffisante */
    if (ctx->contraintes != NULL &&
        arete->securite < ctx->contraintes->securite_min) return 0;

    /* 5. Depassement du cout maximum */
    if (ctx->contraintes != NULL && ctx->contraintes->cout_max > 0) {
        if (ctx->cout_courant + arete->cout > ctx->contraintes->cout_max) return 0;
    }

    return 1; /* OK, on peut explorer ce chemin */
}

/**
 * @brief Fonction recursive principale du backtracking
 *
 * =============================================================
 * ALGORITHME - Schema general :
 *
 * backtrack(noeud_courant):
 *   SI noeud_courant == destination:
 *     SI contraintes_satisfaites():
 *       SI chemin meilleur que le precedent:
 *         sauvegarder comme meilleur chemin
 *     RETOUR
 *
 *   POUR chaque voisin v de noeud_courant:
 *     SI peut_visiter(v):     <- ELAGAGE
 *       marquer v comme visite
 *       ajouter v au chemin
 *       mettre a jour metriques
 *       backtrack(v)          <- RECURSION
 *       retirer v du chemin   <- BACKTRACK
 *       demarquer v
 * =============================================================
 */
void backtrack_recursif(ContexteBacktrack* ctx, int noeud_courant) {
    ctx->nb_appels++;

    /* CAS DE BASE : on est arrive a la destination */
    if (noeud_courant == ctx->destination) {
        if (contraintes_satisfaites(ctx, ctx->destination)) {
            ctx->nb_solutions++;
            float score = ctx->contraintes && !ctx->contraintes->optimiser_latence
                          ? ctx->cout_courant
                          : ctx->latence_courante;
            float score_actuel = ctx->meilleur
                          ? (ctx->contraintes && !ctx->contraintes->optimiser_latence
                             ? ctx->meilleur->cout_total
                             : ctx->meilleur->latence_totale)
                          : INFINI;

            if (score < score_actuel) {
                liberer_chemin(ctx->meilleur);
                ctx->meilleur = creer_chemin();
                for (int i = 0; i < ctx->longueur_courante; i++)
                    ajouter_noeud_chemin(ctx->meilleur, ctx->chemin_courant[i]);
                ctx->meilleur->latence_totale     = ctx->latence_courante;
                ctx->meilleur->cout_total         = ctx->cout_courant;
                ctx->meilleur->bande_passante_min = ctx->bp_min_courante;
            }
        }
        return;
    }

    /* Parcourir tous les voisins et appliquer l'elagage */
    Arete* a = ctx->g->noeuds[noeud_courant].aretes;
    while (a != NULL) {
        int v = a->destination;

        /* ELAGAGE : on ne continue que si prometteur */
        if (peut_visiter(ctx, v, a)) {
            /* Sauvegarder l'etat avant exploration */
            float lat_save = ctx->latence_courante;
            float cout_save = ctx->cout_courant;
            float bp_save = ctx->bp_min_courante;

            /* Avancer : marquer, ajouter au chemin, maj metriques */
            ctx->visite[v] = 1;
            ctx->chemin_courant[ctx->longueur_courante++] = v;
            ctx->latence_courante  += a->latence;
            ctx->cout_courant      += a->cout;
            if (a->bande_passante < ctx->bp_min_courante)
                ctx->bp_min_courante = a->bande_passante;

            /* RECURSION */
            backtrack_recursif(ctx, v);

            /* BACKTRACK : restaurer l'etat precedent */
            ctx->visite[v] = 0;
            ctx->longueur_courante--;
            ctx->latence_courante  = lat_save;
            ctx->cout_courant      = cout_save;
            ctx->bp_min_courante   = bp_save;
        }
        a = a->suivant;
    }
}

/**
 * @brief Point d'entree du backtracking contraint
 */
Chemin* chemin_contraint_backtracking(Graphe* g, int src, int dest, Contraintes* c) {
    if (!noeud_valide(g, src) || !noeud_valide(g, dest)) return NULL;

    int V = g->nb_noeuds;

    /* Initialiser le contexte */
    ContexteBacktrack ctx;
    ctx.g                  = g;
    ctx.source             = src;
    ctx.destination        = dest;
    ctx.contraintes        = c;
    ctx.visite             = creer_tableau_int(V, 0);
    ctx.chemin_courant     = creer_tableau_int(V + 1, -1);
    ctx.longueur_courante  = 0;
    ctx.latence_courante   = 0.0f;
    ctx.cout_courant       = 0.0f;
    ctx.bp_min_courante    = INFINI;
    ctx.meilleur           = NULL;
    ctx.nb_solutions       = 0;
    ctx.nb_appels          = 0;

    /* Verifier que la source n'est pas exclue */
    if (c != NULL && contient(c->noeuds_exclus, c->nb_noeuds_exclus, src)) {
        afficher_erreur("La source est dans les noeuds exclus !");
        free(ctx.visite);
        free(ctx.chemin_courant);
        return NULL;
    }

    /* Demarrer depuis la source */
    ctx.visite[src] = 1;
    ctx.chemin_courant[ctx.longueur_courante++] = src;

    double temps_debut = obtenir_temps_ms();

    /* Lancer le backtracking */
    backtrack_recursif(&ctx, src);

    double duree = mesurer_temps(temps_debut, obtenir_temps_ms());

    /* Afficher les statistiques d'exploration */
    printf("\n  Backtracking termine :\n");
    printf("    Appels recursifs  : %d\n", ctx.nb_appels);
    printf("    Solutions valides : %d\n", ctx.nb_solutions);
    printf("    Temps d'execution : %.3f ms\n", duree);

    free(ctx.visite);
    free(ctx.chemin_courant);
    return ctx.meilleur;
}

/* =========================================================
 * K PLUS COURTS CHEMINS (Diviser pour Regner)
 *
 * Approche inspiree de l'algorithme de Yen (1971)
 * Complexite : O(K * V * (V + E) * log V)
 * ========================================================= */

Chemin** k_plus_courts_chemins(Graphe* g, int src, int dest, int k) {
    if (k <= 0 || k > K_MAX_CHEMINS) k = K_MAX_CHEMINS;

    Chemin** resultats = (Chemin**)calloc(k, sizeof(Chemin*));
    VERIF_NULL(resultats, "k_plus_courts_chemins : allocation echouee");

    /* Tableau pour marquer les aretes supprimees */
    int nb_noeuds = g->nb_noeuds;
    int* noeuds_supprimes = creer_tableau_int(nb_noeuds, 0);

    /* 1er chemin : Dijkstra standard */
    ResultatRoutage* r = dijkstra(g, src);
    if (r == NULL) {
        free(noeuds_supprimes);
        return resultats;
    }
    resultats[0] = reconstruire_chemin(r, dest, g);
    liberer_resultat_routage(r);

    if (resultats[0] == NULL) {
        free(noeuds_supprimes);
        return resultats;
    }

    /* Chemins 2 a k : exploration des variantes */
    for (int i = 1; i < k; i++) {
        Chemin* precedent = resultats[i - 1];
        if (precedent == NULL) break;

        Chemin* meilleur_variante = NULL;
        float   meilleur_dist = INFINI;

        /* Parcourir les noeuds du chemin precedent comme points de deviation */
        NoeudChemin* spur_node = precedent->noeuds;
        int spur_idx = 0;

        while (spur_node != NULL && spur_node->suivant != NULL) {
            int spur_id = spur_node->id_noeud;

            /* Supprimer temporairement ce noeud sauf lui-meme */
            noeuds_supprimes[spur_id] = 0;
            for (int j = 0; j < i; j++) {
                /* Marquer les aretes des chemins precedents depuis spur_id */
                if (resultats[j] != NULL) {
                    NoeudChemin* nc = resultats[j]->noeuds;
                    int idx = 0;
                    while (nc != NULL) {
                        if (idx == spur_idx && nc->suivant != NULL) {
                            noeuds_supprimes[nc->suivant->id_noeud] = 1;
                        }
                        nc = nc->suivant;
                        idx++;
                    }
                }
            }

            /* Trouver chemin depuis spur_id vers dest sans noeuds supprimes */
            Contraintes* c_temp = creer_contraintes(0.0f, INFINI, 0);
            for (int j = 0; j < nb_noeuds; j++) {
                if (noeuds_supprimes[j] && j != spur_id && j != dest)
                    ajouter_noeud_exclu(c_temp, j);
            }

            Chemin* spur_path = chemin_contraint_backtracking(g, spur_id, dest, c_temp);
            liberer_contraintes(c_temp);

            if (spur_path != NULL && spur_path->latence_totale < meilleur_dist) {
                liberer_chemin(meilleur_variante);
                meilleur_variante = spur_path;
                meilleur_dist     = spur_path->latence_totale;
            } else {
                liberer_chemin(spur_path);
            }

            /* Reinitialiser les suppressions */
            for (int j = 0; j < nb_noeuds; j++) noeuds_supprimes[j] = 0;

            spur_node = spur_node->suivant;
            spur_idx++;
        }

        resultats[i] = meilleur_variante;
        if (meilleur_variante == NULL) break; /* Plus de chemins */
    }

    free(noeuds_supprimes);
    return resultats;
}

void afficher_k_chemins(Chemin** chemins, int k, Graphe* g __attribute__((unused))) {
    afficher_titre_section("K PLUS COURTS CHEMINS");
    for (int i = 0; i < k; i++) {
        if (chemins[i] == NULL) {
            printf("  Chemin #%d : " COULEUR_ROUGE "Non disponible\n" COULEUR_RESET, i + 1);
            continue;
        }
        printf(COULEUR_JAUNE "\n  Chemin #%d :\n" COULEUR_RESET, i + 1);
        afficher_chemin(chemins[i]);
    }
}

void liberer_k_chemins(Chemin** chemins, int k) {
    if (chemins == NULL) return;
    for (int i = 0; i < k; i++) liberer_chemin(chemins[i]);
    free(chemins);
}
