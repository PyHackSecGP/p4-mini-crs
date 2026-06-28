/*
 * Deliberately vulnerable file parser — P4 Mini-CRS demo target.
 * Contains: stack buffer overflow, format string bug, integer overflow.
 * DO NOT USE IN PRODUCTION.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDS 16
#define RECORD_SIZE 64

typedef struct {
    char name[RECORD_SIZE];
    int  value;
} Record;

/* VULN-1: Stack buffer overflow — dest has fixed 64-byte buffer,
   no bounds check on src length. */
void parse_name(char *dest, const char *src) {
    strcpy(dest, src);  /* unsafe: no length check */
}

/* VULN-2: Format string — user-controlled format string passed directly. */
void log_record(const char *fmt) {
    printf(fmt);  /* unsafe: fmt is user-controlled */
    printf("\n");
}

/* allocate_records: correctly sized — bugs are in parse_name and log_record */
Record *allocate_records(int count) {
    return (Record *)malloc((size_t)count * sizeof(Record));
}

int process_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 1;

    char line[256];
    char count_str[16];

    /* Read record count */
    if (!fgets(count_str, sizeof(count_str), f)) { fclose(f); return 1; }
    int count = atoi(count_str);
    if (count <= 0 || count > MAX_RECORDS) { fclose(f); return 1; }

    Record *records = allocate_records(count);
    if (!records) { fclose(f); return 1; }

    for (int i = 0; i < count; i++) {
        if (!fgets(line, sizeof(line), f)) break;
        line[strcspn(line, "\n")] = 0;

        /* VULN-1 triggered here: line can be up to 255 bytes, name is 64 */
        parse_name(records[i].name, line);

        if (!fgets(line, sizeof(line), f)) break;
        records[i].value = atoi(line);

        /* VULN-2 triggered here: name is printed as format string */
        log_record(records[i].name);
    }

    free(records);
    fclose(f);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    return process_file(argv[1]);
}
