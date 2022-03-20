#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TTT
int main() {
#ifdef TTT
    printf("%s", "test");
#endif
    return 0;
}