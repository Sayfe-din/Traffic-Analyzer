#ifndef HTTP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <regex.h>

typedef struct _http{
	char *Method;
	char *Version;
} HTTP;

typedef HTTP* PHTTP; 

void extract_HTTP(PHTTP http, char **line, FILE *f, int *offset, unsigned int *CheckTCP);

char flush_data(char **line, FILE *f, unsigned int *CheckTCP);

void free_PHTTP(PHTTP http);

#endif

