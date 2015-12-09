#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

void init();
void logOutput(char *buf, int n);
void logInput(char *buf, int n);
void outputFilter(char *buf, int n);
int inputFilter(char *buf, int n);
