/* Owned public test probe. Compile and inspect only; never execute or dlopen it. */
#include <stdio.h>
__attribute__((visibility("default"))) int public_add(int left, int right) {
    return left + right;
}
__attribute__((visibility("default"))) int public_banner(void) {
    return puts("Getzilla public static probe");
}
int probe_hidden(void) { return 17; }
