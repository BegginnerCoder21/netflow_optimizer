/* =========================================================
 * utils.c - Fonctions utilitaires generales
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#define _POSIX_C_SOURCE 200809L
#include "utils.h"

/* =========================================================
 * Affichage
 * ========================================================= */

void afficher_banniere(void) {
    printf("\n");
    printf(COULEUR_CYAN COULEUR_GRAS);
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║      NetFlow Optimizer & Security Analyzer  v%s       ║\n", VERSION);
    printf("║          UVCI - ALC2101 - Annee 2025-2026               ║\n");
    printf("║     Algorithmique et Complexite - Master Informatique   ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf(COULEUR_RESET "\n");
}

void afficher_separateur(void) {
    printf(COULEUR_BLEU
        "──────────────────────────────────────────────────────────\n"
        COULEUR_RESET);
}

void afficher_titre_section(const char* titre) {
    printf("\n" COULEUR_GRAS COULEUR_JAUNE);
    printf("  ▶  %s\n", titre);
    printf(COULEUR_RESET);
    afficher_separateur();
}

void afficher_succes(const char* message) {
    printf(COULEUR_VERT "  [OK] %s\n" COULEUR_RESET, message);
}

void afficher_erreur(const char* message) {
    fprintf(stderr, COULEUR_ROUGE "  [ERREUR] %s\n" COULEUR_RESET, message);
}

void afficher_avertissement(const char* message) {
    printf(COULEUR_JAUNE "  [ATTENTION] %s\n" COULEUR_RESET, message);
}

void afficher_info(const char* message) {
    printf(COULEUR_BLEU "  [INFO] %s\n" COULEUR_RESET, message);
}

/* =========================================================
 * Saisie securisee
 * ========================================================= */

void vider_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int saisir_entier(const char* message, int min, int max) {
    int valeur;
    int ok = 0;
    while (!ok) {
        printf(COULEUR_CYAN "  %s [%d-%d] : " COULEUR_RESET, message, min, max);
        if (scanf("%d", &valeur) == 1 && valeur >= min && valeur <= max) {
            ok = 1;
        } else {
            afficher_avertissement("Valeur invalide. Veuillez reessayer.");
        }
        vider_buffer();
    }
    return valeur;
}

float saisir_flottant(const char* message, float min, float max) {
    float valeur;
    int ok = 0;
    while (!ok) {
        printf(COULEUR_CYAN "  %s [%.1f-%.1f] : " COULEUR_RESET, message, min, max);
        if (scanf("%f", &valeur) == 1 && valeur >= min && valeur <= max) {
            ok = 1;
        } else {
            afficher_avertissement("Valeur invalide. Veuillez reessayer.");
        }
        vider_buffer();
    }
    return valeur;
}

void saisir_chaine(const char* message, char* buffer, int taille_max) {
    printf(COULEUR_CYAN "  %s : " COULEUR_RESET, message);
    if (fgets(buffer, taille_max, stdin) != NULL) {
        /* Supprimer le saut de ligne final */
        int len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
    }
}

/* =========================================================
 * Mesure de performance
 * Complexite : O(1) pour chaque appel
 * ========================================================= */

double obtenir_temps_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

double mesurer_temps(double debut, double fin) {
    return fin - debut;
}

void afficher_benchmark(const char* nom_algo, int nb_noeuds, double duree_ms) {
    printf(COULEUR_MAGENTA
        "  %-30s | Noeuds: %5d | Temps: %8.3f ms\n"
        COULEUR_RESET, nom_algo, nb_noeuds, duree_ms);
}

/* =========================================================
 * Tableaux
 * Complexite : O(n) pour la creation et l'initialisation
 * ========================================================= */

int* creer_tableau_int(int taille, int valeur) {
    int* tab = (int*)malloc(taille * sizeof(int));
    VERIF_NULL(tab, "Allocation tableau int echouee");
    for (int i = 0; i < taille; i++) tab[i] = valeur;
    return tab;
}

float* creer_tableau_float(int taille, float valeur) {
    float* tab = (float*)malloc(taille * sizeof(float));
    VERIF_NULL(tab, "Allocation tableau float echouee");
    for (int i = 0; i < taille; i++) tab[i] = valeur;
    return tab;
}

/**
 * @brief Verifie si valeur est dans le tableau
 * @complexity O(n) - parcours lineaire
 */
int contient(int* tableau, int taille, int valeur) {
    for (int i = 0; i < taille; i++) {
        if (tableau[i] == valeur) return 1;
    }
    return 0;
}

/* =========================================================
 * Menu principal
 * ========================================================= */

void afficher_menu_principal(void) {
    printf("\n");
    printf(COULEUR_GRAS COULEUR_CYAN
        "╔══════════════════════════════════════════════════════════╗\n"
        "║                     MENU PRINCIPAL                      ║\n"
        "╚══════════════════════════════════════════════════════════╝\n"
        COULEUR_RESET);

    printf(COULEUR_JAUNE "\n  === GESTION DU RESEAU ===\n" COULEUR_RESET);
    printf("   1. Charger un reseau depuis fichier\n");
    printf("   2. Creer un reseau manuellement\n");
    printf("   3. Generer un reseau aleatoire\n");
    printf("   4. Afficher le reseau (liste d'adjacence)\n");
    printf("   5. Afficher le reseau (matrice d'adjacence)\n");
    printf("   6. Sauvegarder le reseau\n");

    printf(COULEUR_JAUNE "\n  === ROUTAGE OPTIMAL ===\n" COULEUR_RESET);
    printf("   7. Dijkstra - Plus court chemin\n");
    printf("   8. Bellman-Ford - Plus court chemin\n");
    printf("   9. Comparer Dijkstra vs Bellman-Ford\n");
    printf("  10. Chemin avec contraintes (backtracking)\n");
    printf("  11. K plus courts chemins alternatifs\n");

    printf(COULEUR_JAUNE "\n  === SECURITE & ANOMALIES ===\n" COULEUR_RESET);
    printf("  12. Parcours DFS\n");
    printf("  13. Parcours BFS\n");
    printf("  14. Detecter les cycles (boucles de routage)\n");
    printf("  15. Points d'articulation (noeuds critiques)\n");
    printf("  16. Ponts critiques (aretes critiques)\n");
    printf("  17. Composantes fortement connexes (Kosaraju)\n");
    printf("  18. Rapport de securite complet\n");

    printf(COULEUR_JAUNE "\n  === SIMULATION DE FLUX ===\n" COULEUR_RESET);
    printf("  19. Simuler file de paquets\n");
    printf("  20. Afficher statistiques de flux\n");

    printf(COULEUR_JAUNE "\n  === BENCHMARKS ===\n" COULEUR_RESET);
    printf("  21. Mesurer performances (tous algorithmes)\n");

    printf(COULEUR_ROUGE "\n   0. Quitter\n" COULEUR_RESET);
    afficher_separateur();
}
