#ifndef IP


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct _ip{
	unsigned char V;
	unsigned char IHL;
	unsigned char TOS;
	unsigned short int Length;
	unsigned char TTL;
	unsigned char Proto;
	unsigned int HCheck;
	unsigned int IPS;
	unsigned int IPD;
} IP;

typedef IP* PIP;

void abort_format();

int extract_ALL_IP(PIP ip, char **line, FILE *f,unsigned int *CheckIP, unsigned int *CheckTCP);

void print_IP(PIP ip, unsigned int *Check);

void free_PIP(PIP ip);

#endif

