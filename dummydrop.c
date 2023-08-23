#include <stdio.h>
#include <string.h>

void cutFile(FILE* f){

    FILE* wf = fopen("./top-1m_r.txt","w");
    if (wf == NULL) {
        printf("Error opening write file.\n");
        return;
    }

    char str[100];
    while(fgets(str, sizeof(str), f) != NULL) {
        
        char *token = strtok(str, ",");
        token = strtok(NULL, "\n");
        if (token != NULL) {
            char str2[105]; // size increased to accommodate the "www." + token + '\0'
            sprintf(str2, "www.%s", token); // concatenate "www." and token into str2
            printf("%s\n", str2);
            fputs(str2, wf);
            fputs("\n", wf); // add newline to the output file for each entry
        }
    }

    fclose(wf);
}

int main() {
    FILE *f = fopen("./top-1m.txt", "r");
    if (f == NULL) {
        printf("Error opening file.\n");
        return 1;
    }
    cutFile(f);
    fclose(f);
    return 0;
}
