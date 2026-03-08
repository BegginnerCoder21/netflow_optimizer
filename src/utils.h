#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/* =========================================================
 * utils.h - Fonctions utilitaires générales
 * Projet : NetFlow Optimizer & Security Analyzer
 * Cours  : ALC2101 - Algorithmique et Complexite
 * UVCI   - Annee 2025-2026
 * ========================================================= */

#define TAILLE_MAX_NOM       50
#define TAILLE_MAX_BUFFER    256
#define TAILLE_MAX_NOEUDS    1000
#define INFINI               1e9f
#define VERSION              "1.0.0"

/* Codes couleurs ANSI */
#define COULEUR_RESET        "\033[0m"
#define COULEUR_ROUGE        "\033[31m"
#define COULEUR_VERT         "\033[32m"
#define COULEUR_JAUNE        "\033[33m"
#define COULEUR_BLEU         "\033[34m"
#define COULEUR_MAGENTA      "\033[35m"
#define COULEUR_CYAN         "\033[36m"
#define COULEUR_GRAS         "\033[1m"

#define MIN(a, b)   ((a) < (b) ? (a) : (b))
#define MAX(a, b)   ((a) > (b) ? (a) : (b))
#define VERIF_NULL(ptr, msg) \
    do { if ((ptr) == NULL) { fprintf(stderr, "[ERREUR] %s\n", msg); exit(EXIT_FAILURE); } } while(0)

void afficher_banniere(void);
void afficher_separateur(void);
void afficher_titre_section(const char* titre);
void afficher_succes(const char* message);
void afficher_erreur(const char* message);
void afficher_avertissement(const char* message);
void afficher_info(const char* message);
int  saisir_entier(const char* message, int min, int max);
float saisir_flottant(const char* message, float min, float max);
void saisir_chaine(const char* message, char* buffer, int taille_max);
double obtenir_temps_ms(void);
double mesurer_temps(double debut, double fin);
void afficher_benchmark(const char* nom_algo, int nb_noeuds, double duree_ms);
int*   creer_tableau_int(int taille, int valeur);
float* creer_tableau_float(int taille, float valeur);
int  contient(int* tableau, int taille, int valeur);
void vider_buffer(void);
void afficher_menu_principal(void);

#endif /* UTILS_H */
