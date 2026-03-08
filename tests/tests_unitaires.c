/* =========================================================
 * tests_unitaires.c - Tests unitaires exhaustifs (+2 pts bonus)
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#include "../src/utils.h"
#include "../src/graphe.h"
#include "../src/liste_chainee.h"
#include "../src/dijkstra.h"
#include "../src/backtracking.h"
#include "../src/securite.h"

/* Compteurs de tests */
static int tests_total  = 0;
static int tests_passes = 0;
static int tests_echecs = 0;

/* Macro d'assertion */
#define ASSERT(condition, message) do { \
    tests_total++; \
    if (condition) { \
        printf(COULEUR_VERT "  [PASS] %s\n" COULEUR_RESET, message); \
        tests_passes++; \
    } else { \
        printf(COULEUR_ROUGE "  [FAIL] %s (ligne %d)\n" COULEUR_RESET, message, __LINE__); \
        tests_echecs++; \
    } \
} while(0)

/* =========================================================
 * Tests - Pile
 * ========================================================= */
void test_pile(void) {
    afficher_titre_section("TESTS : Pile");
    Pile* p = creer_pile();
    ASSERT(pile_est_vide(p), "Pile vide a la creation");
    empiler(p, 10); empiler(p, 20); empiler(p, 30);
    ASSERT(!pile_est_vide(p), "Pile non vide apres 3 empilages");
    ASSERT(sommet_pile(p) == 30, "Sommet = 30 (LIFO)");
    ASSERT(depiler(p) == 30, "Depiler = 30");
    ASSERT(depiler(p) == 20, "Depiler = 20");
    ASSERT(depiler(p) == 10, "Depiler = 10");
    ASSERT(pile_est_vide(p), "Pile vide apres tout depiler");
    ASSERT(depiler(p) == -1, "Depiler pile vide = -1");
    liberer_pile(p);
}

/* =========================================================
 * Tests - File BFS
 * ========================================================= */
void test_file_bfs(void) {
    afficher_titre_section("TESTS : File BFS");
    FileBFS* f = creer_file_bfs();
    ASSERT(file_bfs_est_vide(f), "File BFS vide a la creation");
    enfiler_bfs(f, 1); enfiler_bfs(f, 2); enfiler_bfs(f, 3);
    ASSERT(!file_bfs_est_vide(f), "File non vide apres 3 enfilages");
    ASSERT(defiler_bfs(f) == 1, "Defiler = 1 (FIFO)");
    ASSERT(defiler_bfs(f) == 2, "Defiler = 2");
    ASSERT(defiler_bfs(f) == 3, "Defiler = 3");
    ASSERT(file_bfs_est_vide(f), "File vide apres tout defiler");
    liberer_file_bfs(f);
}

/* =========================================================
 * Tests - File de priorite
 * ========================================================= */
void test_file_priorite(void) {
    afficher_titre_section("TESTS : File de priorite (Paquets)");
    FileAttente* f = creer_file(10);
    ASSERT(file_est_vide(f), "File vide a la creation");

    Paquet* p1 = creer_paquet(1, 3, 1.0f, 0, 5);
    Paquet* p2 = creer_paquet(2, 8, 2.0f, 1, 6);
    Paquet* p3 = creer_paquet(3, 5, 0.5f, 2, 7);

    enqueue(f, p1); enqueue(f, p2); enqueue(f, p3);
    ASSERT(f->taille_actuelle == 3, "File contient 3 paquets");

    Paquet* extrait = dequeue(f);
    ASSERT(extrait != NULL, "Dequeue non NULL");
    ASSERT(extrait->priorite == 8, "Premier extrait = priorite 8 (max)");
    liberer_paquet(extrait);

    extrait = dequeue(f);
    ASSERT(extrait->priorite == 5, "Deuxieme extrait = priorite 5");
    liberer_paquet(extrait);

    extrait = dequeue(f);
    ASSERT(extrait->priorite == 3, "Troisieme extrait = priorite 3");
    liberer_paquet(extrait);

    ASSERT(file_est_vide(f), "File vide apres 3 dequeues");
    liberer_file(f);
}

/* =========================================================
 * Tests - Graphe
 * ========================================================= */
void test_graphe(void) {
    afficher_titre_section("TESTS : Graphe");

    Graphe* g = creer_graphe(5, 1);
    ASSERT(g != NULL, "Graphe cree non NULL");
    ASSERT(g->nb_noeuds == 5, "Graphe a 5 noeuds");
    ASSERT(g->nb_aretes == 0, "Graphe vide a 0 aretes");

    ajouter_noeud(g, 0, "Paris");
    ajouter_noeud(g, 1, "Lyon");
    ajouter_noeud(g, 2, "Marseille");
    ASSERT(strcmp(obtenir_nom_noeud(g, 0), "Paris") == 0, "Noeud 0 = Paris");
    ASSERT(strcmp(obtenir_nom_noeud(g, 1), "Lyon") == 0, "Noeud 1 = Lyon");

    ajouter_arete(g, 0, 1, 10.0f, 100.0f, 5.0f, 8);
    ajouter_arete(g, 1, 2, 15.0f, 80.0f, 3.0f, 7);
    ajouter_arete(g, 0, 2, 30.0f, 50.0f, 8.0f, 6);
    ASSERT(g->nb_aretes == 3, "Graphe a 3 aretes");
    ASSERT(arete_existe(g, 0, 1), "Arete 0->1 existe");
    ASSERT(!arete_existe(g, 1, 0), "Arete 1->0 n'existe pas (oriente)");

    Arete* a = obtenir_arete(g, 0, 1);
    ASSERT(a != NULL, "Obtenir arete 0->1 non NULL");
    ASSERT(a->latence == 10.0f, "Latence arete 0->1 = 10");

    /* Test matrice */
    ASSERT(g->matrice_adjacence[0][1] == 10.0f, "Matrice[0][1] = 10");
    ASSERT(g->matrice_adjacence[1][0] >= INFINI, "Matrice[1][0] = INFINI");

    /* Test suppression */
    supprimer_arete(g, 0, 1);
    ASSERT(!arete_existe(g, 0, 1), "Arete 0->1 supprimee");
    ASSERT(g->nb_aretes == 2, "Graphe a 2 aretes apres suppression");

    detruire_graphe(g);
    ASSERT(1, "Graphe libere sans crash");
}

/* =========================================================
 * Tests - Dijkstra
 * ========================================================= */
void test_dijkstra(void) {
    afficher_titre_section("TESTS : Dijkstra");

    /* Graphe simple de 4 noeuds avec chemin connu */
    /*
     *  0 --10--> 1 --5--> 3
     *  |                  ^
     *  +---20-----------> +
     *  |
     *  +--15--> 2 --5---> 3
     */
    Graphe* g = creer_graphe(4, 1);
    ajouter_arete(g, 0, 1, 10.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g, 0, 2, 15.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g, 0, 3, 20.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g, 1, 3, 5.0f,  100.0f, 1.0f, 10);
    ajouter_arete(g, 2, 3, 5.0f,  100.0f, 1.0f, 10);

    ResultatRoutage* r = dijkstra(g, 0);
    ASSERT(r != NULL, "Dijkstra retourne resultat non NULL");
    ASSERT(r->distances[0] == 0.0f, "Distance source -> source = 0");
    ASSERT(r->distances[1] == 10.0f, "Distance 0->1 = 10");
    ASSERT(r->distances[2] == 15.0f, "Distance 0->2 = 15");
    ASSERT(r->distances[3] == 15.0f, "Distance 0->3 = 15 (via 1: 10+5)");

    Chemin* c = reconstruire_chemin(r, 3, g);
    ASSERT(c != NULL, "Chemin vers noeud 3 non NULL");
    ASSERT(c->latence_totale == 15.0f, "Latence chemin optimal = 15");

    liberer_chemin(c);
    liberer_resultat_routage(r);
    detruire_graphe(g);
}

/* =========================================================
 * Tests - Bellman-Ford
 * ========================================================= */
void test_bellman_ford(void) {
    afficher_titre_section("TESTS : Bellman-Ford");

    Graphe* g = creer_graphe(4, 1);
    ajouter_arete(g, 0, 1, 10.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g, 0, 2, 15.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g, 1, 3, 5.0f,  100.0f, 1.0f, 10);
    ajouter_arete(g, 2, 3, 5.0f,  100.0f, 1.0f, 10);

    ResultatRoutage* r = bellman_ford(g, 0);
    ASSERT(r != NULL, "Bellman-Ford retourne resultat non NULL");
    ASSERT(r->distances[3] == 15.0f, "BF : Distance 0->3 = 15");
    ASSERT(r->distances[1] == 10.0f, "BF : Distance 0->1 = 10");

    liberer_resultat_routage(r);
    detruire_graphe(g);
}

/* =========================================================
 * Tests - Securite
 * ========================================================= */
void test_securite(void) {
    afficher_titre_section("TESTS : Securite");

    /* Graphe sans cycle */
    Graphe* g1 = creer_graphe(4, 1);
    ajouter_arete(g1, 0, 1, 1.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g1, 1, 2, 1.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g1, 2, 3, 1.0f, 100.0f, 1.0f, 10);
    ASSERT(!detecter_cycles(g1), "Graphe lineaire sans cycle");

    /* Graphe avec cycle */
    Graphe* g2 = creer_graphe(3, 1);
    ajouter_arete(g2, 0, 1, 1.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g2, 1, 2, 1.0f, 100.0f, 1.0f, 10);
    ajouter_arete(g2, 2, 0, 1.0f, 100.0f, 1.0f, 10);
    ASSERT(detecter_cycles(g2), "Graphe avec cycle 0->1->2->0 detecte");

    /* Test Kosaraju */
    int* comp = creer_tableau_int(3, -1);
    int nb_scc = kosaraju(g2, comp);
    ASSERT(nb_scc == 1, "Graphe cyclique = 1 SCC (fortement connexe)");
    free(comp);

    detruire_graphe(g1);
    detruire_graphe(g2);
}

/* =========================================================
 * Tests - Chargement fichier
 * ========================================================= */
void test_chargement_fichier(void) {
    afficher_titre_section("TESTS : Chargement fichier");
    Graphe* g = charger_graphe_fichier("data/reseau_test1.txt");
    ASSERT(g != NULL, "Fichier reseau_test1.txt charge");
    if (g != NULL) {
        ASSERT(g->nb_noeuds == 8, "Test1 : 8 noeuds");
        ASSERT(g->nb_aretes == 13, "Test1 : 13 aretes");
        detruire_graphe(g);
    }
}

/* =========================================================
 * Rapport final
 * ========================================================= */
void afficher_rapport_tests(void) {
    printf("\n");
    afficher_separateur();
    printf(COULEUR_GRAS "\n  RAPPORT FINAL DES TESTS\n\n" COULEUR_RESET);
    printf("  Tests total  : %d\n", tests_total);
    printf(COULEUR_VERT "  Tests passes : %d\n" COULEUR_RESET, tests_passes);
    if (tests_echecs > 0)
        printf(COULEUR_ROUGE "  Tests echecs : %d\n" COULEUR_RESET, tests_echecs);
    else
        printf("  Tests echecs : 0\n");
    printf("\n  Taux de reussite : %.1f%%\n",
           tests_total > 0 ? (float)tests_passes / tests_total * 100.0f : 0.0f);
    afficher_separateur();
    if (tests_echecs == 0)
        afficher_succes("TOUS LES TESTS SONT PASSES !");
    else
        afficher_avertissement("Certains tests ont echoue.");
}

int main(void) {
    afficher_banniere();
    printf(COULEUR_GRAS "  EXECUTION DES TESTS UNITAIRES\n" COULEUR_RESET);
    afficher_separateur();

    test_pile();
    test_file_bfs();
    test_file_priorite();
    test_graphe();
    test_dijkstra();
    test_bellman_ford();
    test_securite();
    test_chargement_fichier();

    afficher_rapport_tests();
    return (tests_echecs == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
