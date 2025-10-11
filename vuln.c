// vuln_cli.c — mini "quiz show" interattivo con vulnerabilità didattiche
// ⚠️ SOLO PER ESERCIZI IN LOCALE / LAB. NON USARE MAI CONTRO SISTEMI NON VOSTRI.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    setbuf(stdout, NULL); 
    char answer[256];

    puts("Benvenuto al Quiz Vulnerabile! (solo in locale)");
    puts("Rispondi alle domande: alcune risposte possono far crashare il programma, e' voluto.");
    puts("Digita 'quit' per uscire senza rischi.");
    puts("");

    // Domanda 1: format-string vulnerability
    fputs("Domanda 1: Come ti chiami? ", stdout);
    fflush(stdout);
    if (!fgets(answer, sizeof answer, stdin)) return 0;
    if (strncmp(answer, "quit", 4) == 0) return 0;
    // Vulnerabilità: passa direttamente l'input a printf
    printf("Ciao ");
    printf(answer);
    putchar('\n');
    

    // SAFE QUESTION A: preferenza colori (non crasha)
    fputs("Domanda 2: Qual è il tuo colore preferito? ", stdout);
    fflush(stdout);
    if (!fgets(answer, sizeof answer, stdin)) return 0;
    if (strncmp(answer, "quit", 4) == 0) return 0;
    // Stampa in modo sicuro
    char buf[300];
    snprintf(buf, sizeof buf, "Che bel colore: %s", answer);
    fputs(buf, stdout);
    fflush(stdout);
    putchar('\n');

    // Domanda 2: stack buffer overflow
    fputs("Domanda 3: Scrivi una parola (max 10 chars consigliati): ", stdout);
    fflush(stdout);
    if (!fgets(answer, sizeof answer, stdin)) return 0;
    if (strncmp(answer, "quit", 4) == 0) return 0;
    // Vulnerabilità: copia in buffer piccolo senza controllo
    {
        char small[16];
        strcpy(small, answer); // overflow se input > 15 caratteri
        printf("Hai scritto: %s", small);
    }
    putchar('\n');

    // SAFE QUESTION B: scelta multipla semplice (A/B/C)
    fputs("Domanda 4: Scegli una opzione (A/B/C): ", stdout);
    fflush(stdout);
    if (!fgets(answer, sizeof answer, stdin)) return 0;
    if (strncmp(answer, "quit", 4) == 0) return 0;
    char choice = answer[0];
    if (choice == 'A' || choice == 'a') puts("Hai scelto A: ottima scelta!");
    else if (choice == 'B' || choice == 'b') puts("Hai scelto B: interessante.");
    else if (choice == 'C' || choice == 'c') puts("Hai scelto C: bene.");
    else puts("Scelta non valida, ma il programma continua.");

    // Domanda 3: numero che può causare integer/heap OOB
    fputs("Domanda 5: Inserisci un numero intero positivo: ", stdout);
    fflush(stdout);
    if (!fgets(answer, sizeof answer, stdin)) return 0;
    if (strncmp(answer, "quit", 4) == 0) return 0;

    long n = strtol(answer, NULL, 10);
    if (n < 0) n = 0;
    size_t count = (size_t)(n * 3); // può overfloware per numeri grandi
    int *arr = (int*)malloc(count * sizeof(int));
    if (arr) {
        for (size_t i = 0; i <= count; ++i) { // off-by-one: scrive arr[count]
            arr[i] = (int)i;
        }
        free(arr);
    }

    puts("Grazie per aver giocato — sessione terminata.");
    return 0;
}