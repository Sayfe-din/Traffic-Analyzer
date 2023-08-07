#ifndef TCP


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct _tcp{
	unsigned short int SrcPort;
	unsigned short int DestPort;
	unsigned int SEQN;
	unsigned int ACKN;
	unsigned char THL;
	unsigned char URG;
	unsigned char ACK;
	unsigned char PSH;
	unsigned char RST;
	unsigned char SYN;
	unsigned char FIN;
	unsigned short int WIN;
	unsigned short int Checksum;
	unsigned short int Urgent;
} TCP;

typedef TCP* PTCP;

int extract_ALL_TCP(PTCP tcp, char **line, FILE *f, char offset, unsigned int *CheckTCP);

void fprint_TCP(PTCP tcp, FILE *file, unsigned int tramenum);

void fprint_reverse_TCP(PTCP tcp, FILE *file, unsigned int tramenum);

void print_TCP(PTCP tcp);

void free_PTCP(PTCP tcp);

#endif


