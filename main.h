#ifndef MAIN
#include "Ethernet.h"
#include "IP.h"
#include "TCP.h"
#include "HTTP.h"

typedef struct _cellframe{
	PEthernet eth;
	PIP ip;
	PTCP tcp;
	PHTTP http;
	struct _cellframe *next;
} CellFrame;

void free_CellFrame(CellFrame *cframe);

extern void abort_format();

void fprint_HTTP(CellFrame *tmp, FILE *file, unsigned int tramenum);

void fprint_reverse_HTTP(CellFrame *tmp, FILE *file, unsigned int tramenum);

void fprint_IP(CellFrame *tmp, FILE *file, unsigned int tramenum);

void fprint_reverse_IP(CellFrame *tmp, FILE *file, unsigned int tramenum);

void save_exchanges(CellFrame *f, char *name);
#endif


