/* =========================================================
 * main.c - Point d'entree principal
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "utils.h"
#include "graphe.h"
#include "liste_chainee.h"
#include "dijkstra.h"
#include "backtracking.h"
#include "securite.h"

/* Graphe courant global pour la session */
static Graphe* graphe_courant = NULL;

/* =========================================================
 * Fonctions d'action du menu
 * ========================================================= */

static void action_charger_fichier(void) {
    char chemin[TAILLE_MAX_BUFFER];
    printf("\n  Fichiers disponibles :\n");
    printf("    data/reseau_test1.txt  (8 noeuds)\n");
    printf("    data/reseau_test2.txt  (12 noeuds)\n");
    printf("    data/reseau_reel.txt   (si disponible)\n\n");
    saisir_chaine("Chemin du fichier", chemin, TAILLE_MAX_BUFFER);
    if (graphe_courant != NULL) detruire_graphe(graphe_courant);
    graphe_courant = charger_graphe_fichier(chemin);
}

static void action_creer_manuel(void) {
    int n = saisir_entier("Nombre de noeuds", 2, TAILLE_MAX_NOEUDS);
    int oriente = saisir_entier("Graphe oriente ? (1=oui, 0=non)", 0, 1);
    if (graphe_courant != NULL) detruire_graphe(graphe_courant);
    graphe_courant = creer_graphe(n, oriente);

    afficher_info("Entrez le nom de chaque noeud :");
    for (int i = 0; i < n; i++) {
        char nom[TAILLE_MAX_NOM];
        char msg[64];
        snprintf(msg, 64, "Nom du noeud %d", i);
        saisir_chaine(msg, nom, TAILLE_MAX_NOM);
        ajouter_noeud(graphe_courant, i, nom);
    }

    int m = saisir_entier("Nombre d'aretes a ajouter", 0, n * n);
    for (int i = 0; i < m; i++) {
        printf("\n  Arete %d/%d :\n", i + 1, m);
        int src  = saisir_entier("  Source", 0, n - 1);
        int dest = saisir_entier("  Destination", 0, n - 1);
        float lat  = saisir_flottant("  Latence (ms)", 0.1f, 10000.0f);
        float bp   = saisir_flottant("  Bande passante (Mbps)", 0.1f, 100000.0f);
        float cout = saisir_flottant("  Cout", 0.0f, 10000.0f);
        int   sec  = saisir_entier("  Securite (0-10)", 0, 10);
        ajouter_arete(graphe_courant, src, dest, lat, bp, cout, sec);
    }
    afficher_succes("Reseau cree avec succes.");
}

static void action_reseau_aleatoire(void) {
    int n          = saisir_entier("Nombre de noeuds", 2, 500);
    int oriente    = saisir_entier("Graphe oriente ? (1=oui, 0=non)", 0, 1);
    float densite  = saisir_flottant("Densite des aretes (0.1 a 0.9)", 0.1f, 0.9f);
    if (graphe_courant != NULL) detruire_graphe(graphe_courant);
    graphe_courant = generer_graphe_aleatoire(n, densite, oriente);
}

static void verifier_graphe_charge(void) {
    if (graphe_courant == NULL) {
        afficher_avertissement("Aucun reseau charge. Utilisez l'option 1, 2 ou 3.");
    }
}

static void action_dijkstra(void) {
    verifier_graphe_charge();
    if (!graphe_courant) return;
    int src  = saisir_entier("Noeud source", 0, graphe_courant->nb_noeuds - 1);
    int dest = saisir_entier("Noeud destination (-1 = tous)", -1, graphe_courant->nb_noeuds - 1);
    ResultatRoutage* r = dijkstra(graphe_courant, src);
    if (r == NULL) { afficher_erreur("Dijkstra a echoue."); return; }
    if (dest == -1) afficher_tous_chemins(r, graphe_courant);
    else            afficher_chemin_detail(r, dest, graphe_courant);
    printf("\n  Temps d'execution : %.4f ms\n", r->temps_exec_ms);
    liberer_resultat_routage(r);
}

static void action_bellman_ford(void) {
    verifier_graphe_charge();
    if (!graphe_courant) return;
    int src  = saisir_entier("Noeud source", 0, graphe_courant->nb_noeuds - 1);
    int dest = saisir_entier("Noeud destination (-1 = tous)", -1, graphe_courant->nb_noeuds - 1);
    ResultatRoutage* r = bellman_ford(graphe_courant, src);
    if (r == NULL) { afficher_erreur("Bellman-Ford a echoue ou cycle negatif."); return; }
    if (dest == -1) afficher_tous_chemins(r, graphe_courant);
    else            afficher_chemin_detail(r, dest, graphe_courant);
    printf("\n  Temps d'execution : %.4f ms\n", r->temps_exec_ms);
    liberer_resultat_routage(r);
}

static void action_backtracking(void) {
    verifier_graphe_charge();
    if (!graphe_courant) return;
    int src  = saisir_entier("Noeud source", 0, graphe_courant->nb_noeuds - 1);
    int dest = saisir_entier("Noeud destination", 0, graphe_courant->nb_noeuds - 1);

    printf("\n  Configuration des contraintes :\n");
    float bp_min = saisir_flottant("  BP minimum (Mbps, 0=aucune)", 0.0f, 100000.0f);
    float c_max  = saisir_flottant("  Cout maximum (0=illimite)", 0.0f, 100000.0f);
    int   sec    = saisir_entier("  Securite minimum (0-10)", 0, 10);

    Contraintes* c = creer_contraintes(bp_min, c_max > 0 ? c_max : INFINI, sec);

    int nb_oblg = saisir_entier("  Noeuds obligatoires a ajouter", 0, graphe_courant->nb_noeuds);
    for (int i = 0; i < nb_oblg; i++) {
        int id = saisir_entier("    ID noeud obligatoire", 0, graphe_courant->nb_noeuds - 1);
        ajouter_noeud_oblg(c, id);
    }

    int nb_excl = saisir_entier("  Noeuds a exclure", 0, graphe_courant->nb_noeuds);
    for (int i = 0; i < nb_excl; i++) {
        int id = saisir_entier("    ID noeud exclu", 0, graphe_courant->nb_noeuds - 1);
        ajouter_noeud_exclu(c, id);
    }

    afficher_contraintes(c);
    Chemin* chemin = chemin_contraint_backtracking(graphe_courant, src, dest, c);
    if (chemin != NULL) {
        afficher_titre_section("MEILLEUR CHEMIN AVEC CONTRAINTES");
        afficher_chemin(chemin);
        liberer_chemin(chemin);
    } else {
        afficher_avertissement("Aucun chemin satisfaisant les contraintes n'a ete trouve.");
    }
    liberer_contraintes(c);
}

static void action_k_chemins(void) {
    verifier_graphe_charge();
    if (!graphe_courant) return;
    int src = saisir_entier("Noeud source", 0, graphe_courant->nb_noeuds - 1);
    int dst = saisir_entier("Noeud destination", 0, graphe_courant->nb_noeuds - 1);
    int k   = saisir_entier("Nombre de chemins K", 1, K_MAX_CHEMINS);
    Chemin** chemins = k_plus_courts_chemins(graphe_courant, src, dst, k);
    afficher_k_chemins(chemins, k, graphe_courant);
    liberer_k_chemins(chemins, k);
}

static void action_securite_complete(void) {
    verifier_graphe_charge();
    if (!graphe_courant) return;
    ResultatSecurite* r = analyser_securite_complete(graphe_courant);
    afficher_rapport_securite(r, graphe_courant);
    liberer_resultat_securite(r);
}

static void action_simulation_flux(void) {
    verifier_graphe_charge();
    if (!graphe_courant) return;
    int nb_paq = saisir_entier("Nombre de paquets a simuler", 10, 10000);
    int cap    = saisir_entier("Capacite de la file (0=illimitee)", 0, 10000);
    StatistiquesFlux stats = simuler_flux(nb_paq, cap > 0 ? cap : nb_paq * 2,
                                           graphe_courant->nb_noeuds);
    afficher_statistiques(&stats);
}

static void action_benchmarks(void) {
    afficher_titre_section("BENCHMARKS DE PERFORMANCE");
    afficher_info("Generation de graphes de differentes tailles...\n");

    int tailles[] = {10, 50, 100, 200, 500};
    int nb_tailles = 5;

    printf("  %-30s | %-8s | %-12s | %-12s\n",
           "Algorithme", "Noeuds", "Temps(ms)", "Complexite");
    afficher_separateur();

    for (int t = 0; t < nb_tailles; t++) {
        int n = tailles[t];
        Graphe* g = generer_graphe_aleatoire(n, 0.3f, 1);

        /* Dijkstra */
        double debut = obtenir_temps_ms();
        ResultatRoutage* r1 = dijkstra(g, 0);
        double duree_d = mesurer_temps(debut, obtenir_temps_ms());
        if (r1) liberer_resultat_routage(r1);
        afficher_benchmark("Dijkstra", n, duree_d);

        /* Bellman-Ford */
        debut = obtenir_temps_ms();
        ResultatRoutage* r2 = bellman_ford(g, 0);
        double duree_b = mesurer_temps(debut, obtenir_temps_ms());
        if (r2) liberer_resultat_routage(r2);
        afficher_benchmark("Bellman-Ford", n, duree_b);

        /* Securite (DFS + points artic + Kosaraju) */
        debut = obtenir_temps_ms();
        ResultatSecurite* rs = analyser_securite_complete(g);
        double duree_s = mesurer_temps(debut, obtenir_temps_ms());
        if (rs) liberer_resultat_securite(rs);
        afficher_benchmark("Securite complete", n, duree_s);

        printf("\n");
        detruire_graphe(g);
    }
    afficher_succes("Benchmarks termines.");
}

/* =========================================================
 * BOUCLE PRINCIPALE
 * ========================================================= */

int main(void) {
    afficher_banniere();
    afficher_info("Bienvenue dans NetFlow Optimizer & Security Analyzer");
    afficher_info("Chargez un reseau pour commencer (option 1, 2 ou 3).\n");

    int choix = -1;
    while (choix != 0) {
        afficher_menu_principal();
        choix = saisir_entier("Votre choix", 0, 21);

        switch (choix) {
            case 0:
                afficher_info("Au revoir !");
                if (graphe_courant != NULL) detruire_graphe(graphe_courant);
                return EXIT_SUCCESS;

            case 1:  action_charger_fichier(); break;
            case 2:  action_creer_manuel(); break;
            case 3:  action_reseau_aleatoire(); break;

            case 4:
                verifier_graphe_charge();
                if (graphe_courant) afficher_graphe(graphe_courant);
                break;
            case 5:
                verifier_graphe_charge();
                if (graphe_courant) afficher_matrice(graphe_courant);
                break;
            case 6:
                verifier_graphe_charge();
                if (graphe_courant) {
                    char chemin[TAILLE_MAX_BUFFER];
                    saisir_chaine("Nom du fichier de sauvegarde", chemin, TAILLE_MAX_BUFFER);
                    sauvegarder_graphe(graphe_courant, chemin);
                }
                break;

            case 7:  action_dijkstra(); break;
            case 8:  action_bellman_ford(); break;
            case 9:
                verifier_graphe_charge();
                if (graphe_courant) {
                    int src = saisir_entier("Noeud source", 0, graphe_courant->nb_noeuds - 1);
                    comparer_dijkstra_bellman(graphe_courant, src);
                }
                break;
            case 10: action_backtracking(); break;
            case 11: action_k_chemins(); break;

            case 12:
                verifier_graphe_charge();
                if (graphe_courant) {
                    int dep = saisir_entier("Noeud de depart", 0, graphe_courant->nb_noeuds - 1);
                    dfs_affichage(graphe_courant, dep);
                }
                break;
            case 13:
                verifier_graphe_charge();
                if (graphe_courant) {
                    int dep = saisir_entier("Noeud de depart", 0, graphe_courant->nb_noeuds - 1);
                    bfs_affichage(graphe_courant, dep);
                }
                break;
            case 14:
                verifier_graphe_charge();
                if (graphe_courant) {
                    afficher_titre_section("DETECTION DE CYCLES");
                    int r = detecter_cycles(graphe_courant);
                    if (r) afficher_avertissement("Des cycles ont ete detectes !");
                    else   afficher_succes("Aucun cycle detecte.");
                }
                break;
            case 15: {
                verifier_graphe_charge();
                if (!graphe_courant) break;
                afficher_titre_section("POINTS D'ARTICULATION");
                int* pa = creer_tableau_int(graphe_courant->nb_noeuds, -1);
                int nb = 0;
                trouver_points_articulation(graphe_courant, pa, &nb);
                if (nb == 0) afficher_succes("Aucun point d'articulation.");
                else {
                    printf("  %d point(s) d'articulation :\n", nb);
                    for (int i = 0; i < nb; i++)
                        printf("    [%d] %s\n", pa[i], obtenir_nom_noeud(graphe_courant, pa[i]));
                }
                free(pa);
                break;
            }
            case 16: {
                verifier_graphe_charge();
                if (!graphe_courant) break;
                afficher_titre_section("PONTS CRITIQUES");
                int V = graphe_courant->nb_noeuds;
                int* ps = creer_tableau_int(V * V, -1);
                int* pd = creer_tableau_int(V * V, -1);
                int nb = 0;
                trouver_ponts(graphe_courant, ps, pd, &nb);
                if (nb == 0) afficher_succes("Aucun pont critique.");
                else {
                    printf("  %d pont(s) critique(s) :\n", nb);
                    for (int i = 0; i < nb; i++)
                        printf("    %s --> %s\n",
                               obtenir_nom_noeud(graphe_courant, ps[i]),
                               obtenir_nom_noeud(graphe_courant, pd[i]));
                }
                free(ps); free(pd);
                break;
            }
            case 17: {
                verifier_graphe_charge();
                if (!graphe_courant) break;
                afficher_titre_section("COMPOSANTES FORTEMENT CONNEXES (Kosaraju)");
                int* comp = creer_tableau_int(graphe_courant->nb_noeuds, -1);
                int nb = kosaraju(graphe_courant, comp);
                printf("  Nombre de SCC : %d\n", nb);
                for (int s = 0; s < nb; s++) {
                    printf("  SCC #%d : ", s);
                    for (int i = 0; i < graphe_courant->nb_noeuds; i++)
                        if (comp[i] == s) printf("[%d]%s ", i, obtenir_nom_noeud(graphe_courant, i));
                    printf("\n");
                }
                free(comp);
                break;
            }
            case 18: action_securite_complete(); break;
            case 19: action_simulation_flux(); break;
            case 20: {
                verifier_graphe_charge();
                if (!graphe_courant) break;
                StatistiquesFlux stats = simuler_flux(500, 100, graphe_courant->nb_noeuds);
                afficher_statistiques(&stats);
                break;
            }
            case 21: action_benchmarks(); break;

            default:
                afficher_avertissement("Option invalide.");
                break;
        }

        if (choix != 0) {
            printf("\n");
            afficher_separateur();
            printf("  Appuyez sur Entree pour continuer...");
            vider_buffer();
            getchar();
        }
    }

    if (graphe_courant != NULL) detruire_graphe(graphe_courant);
    return EXIT_SUCCESS;
}
