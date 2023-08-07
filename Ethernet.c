#include "Ethernet.h"

int extract_MAC(PEthernet eth, char **line){
	char *end=0,res=0;
	int offset=strtol(*line,&end,16);
	end=end+2;
	int i=0;
	eth->MACdest=malloc(sizeof(unsigned char )*7);
	while(i<=5){
		eth->MACdest[i]=strtol(end+1,&end,16);
		i++;
	}
	res=i/5;
	i=0;
	eth->MACsrc=malloc(sizeof(unsigned char )*7);
	while(i<=5){
		eth->MACsrc[i]=strtol(end+1,&end,16);
		i++;
	}
	res=res+i/5;
	*line=end+1;
	return res/2; // renvoie 1 si les deux lectures se sont bien passée 0 si au moins une des deux a échoué
}

int extract_PROTO(PEthernet eth, char **line){
	eth->Proto=malloc(sizeof(unsigned char)*3);
	char *end=0;
	eth->Proto[0]=strtol(*line,&end,16);
	eth->Proto[1]=strtol(end+1,&end,16);
	*line=end+1;
	if((eth->Proto[0]==8)&&(eth->Proto[1]==0)){
		return **line;
	}
	return 0;
}

void print_ETHERNET(PEthernet eth){
	//Affichage des champs de l'entete Ethernet dans le terminal
	printf("Ethernet Frame:\n\tMAC address Destination:%02x:%02x:%02x:%02x:%02x:%02x\n\tMAC address Source:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->MACdest[0],eth->MACdest[1],eth->MACdest[2],eth->MACdest[3],eth->MACdest[4],eth->MACdest[5],eth->MACsrc[0],eth->MACsrc[1],eth->MACsrc[2],eth->MACsrc[3],eth->MACsrc[4],eth->MACsrc[5]);
}
void free_PEthernet(PEthernet eth){
	if(!eth){return;}
	free(eth->MACdest);
	free(eth->MACsrc);
	free(eth->Proto);
	free(eth);
	
	return;
}
