#include <stdlib.h>
/* Toolchain calibration only; does not exercise PHP or the reported CVEs. */
int main(int argc, char **argv) {
    volatile int *p = malloc(sizeof(int));
    *p = argc;
    free((void *) p);
    return *p;
}
