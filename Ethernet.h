#ifndef ETH


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct _ethernet{
	unsigned char *MACdest; //unsigned pour eviter l'extension du dernier bit sur tout les bits de poids fort
	unsigned char *MACsrc;
	unsigned char *Proto;
} Ethernet;

typedef Ethernet* PEthernet;

int extract_MAC(PEthernet eth, char **line);

int extract_PROTO(PEthernet eth, char **line);

void print_ETHERNET(PEthernet eth);

void free_PEthernet(PEthernet eth);

#endif


