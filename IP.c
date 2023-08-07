#include "IP.h"

int extract_ALL_IP(PIP ip,char **line, FILE *f, unsigned int *CheckIP,unsigned int *CheckTCP){
	assert(f);
	char *end=0;
	int null=0;
	ip->V=strtol(*line,&end,16);
	
	*CheckIP+=ip->V << 8;
	
	if(*line==end){abort_format();}
	
	ip->IHL=ip->V & 0x0F;		//application du mask pour extraire IHL
	ip->V=ip->V/16;				//decalage de 4 bits a droite
	
	if(*line==end){abort_format();}
	
	ip->TOS=strtol(end,line,16);
	*CheckIP+=ip->TOS;
	
	if(*line==end){abort_format();}
	
	assert(fgets(*line,2000,f));	//fin de ligne: on charge la ligne suivante
	null=strtol(*line,&end,16);
	*line=end+2;
	
	ip->Length=strtol(*line,&end,16) << 8;//decalage de 8 bits a gauche
	
	if(*line==end){abort_format();}
	
	ip->Length+=strtol(end,line,16);//addition du deuxieme octet dans les 8 bits de poid faible
	
	if(*line==end){abort_format();}
	
	null=strtol(*line,&end,16) << 8;		//information non necessaire pour le visualisateur
	null+=strtol(end,line,16);
	*CheckIP+=null;
	
	null=strtol(*line,&end,16) << 8;
	null+=strtol(end,line,16);
	*CheckIP+=null;
	
	if(*line==end){abort_format();}
	
	ip->TTL=strtol(*line,&end,16);
	
	if(*line==end){abort_format();}
	
	ip->Proto=strtol(end,line,16);
	
	if(*line==end){abort_format();}
	
	ip->HCheck=strtol(*line,&end,16) << 8;
	
	if(*line==end){abort_format();}
	
	ip->HCheck+=strtol(end,line,16);
	
	if(*line==end){abort_format();}
	
	ip->IPS=strtol(*line,&end,16) << 24;
	ip->IPS+=(strtol(end,line,16) << 16);
	ip->IPS+=(strtol(*line,&end,16) << 8);
	ip->IPS+=strtol(end,line,16);
	
	if(*line==end){abort_format();}
	
	ip->IPD=strtol(*line,&end,16) << 24;
	ip->IPD+=(strtol(end,line,16) << 16);
	
	assert(fgets(*line,2000,f));
	null=strtol(*line,line,16);	//offset
	*line=*line+2;
	
	ip->IPD+=(strtol(*line,&end,16) << 8);
	ip->IPD+=strtol(end,line,16);
	
	if(*line==end){abort_format();}
	
	//Verification de l'integrité de l'entete IP
	*CheckIP+=ip->TOS;
	*CheckIP+=ip->Length;
	*CheckIP+=(ip->TTL << 8)+ip->Proto;
	*CheckIP+=ip->HCheck;
	*CheckIP+=(ip->IPS >> 16);
	*CheckIP+=(ip->IPS & 0x0000FFFF);
	*CheckIP+=(ip->IPD >> 16);
	*CheckIP+=(ip->IPD & 0x0000FFFF);
	
	*CheckIP+=(*CheckIP >> 16);
	
	//Verification de l'integrite de la pseudo-entete IP pour TCP
	*CheckTCP=(ip->IPS >> 16);
	*CheckTCP+=(ip->IPS & 0x0000FFFF);
	*CheckTCP+=(ip->IPD >> 16);
	*CheckTCP+=(ip->IPD & 0x0000FFFF);
	*CheckTCP+=ip->Proto;
	
	
	
	null=ip->IHL-5;
	int offset=2;
	while(null--){//Passage sur les Options
		int unused=strtol(*line,&end,16) << 8;
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		unused+=strtol(end,line,16);
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
			
			
		*CheckIP+=unused;
		
		unused=strtol(*line,&end,16) << 8;
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		unused+=strtol(end,line,16);
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		*CheckIP+=unused;
		
		if(*line==end){abort_format();}
	}
	
	null=ip->IHL-5;
	return null%4; //retourne le nombre de mots en decalé depuis le dernier octet de l'adresse IP destination dans l'entete IP
}

void print_IP(PIP ip,unsigned int *Check){
	//Affichage des champs de l'entete IP dans le terminal
	printf("\tPacket IP:\n\t\tVersion:%02x\n\t\tIHL:%02x\n\t\tTOS:%02x\n\t\tLength:%04x\n\t\tTTL:%02x\n\t\tProtocol:%02x\n\t\tChecksum:%04x\n\t\tAdresse IP Source:%08x\n\t\tAdresse IP Destination:%08x\n\t\t",ip->V,ip->IHL,ip->TOS,ip->Length,ip->TTL,ip->Proto,ip->HCheck,ip->IPS,ip->IPD);
	if((*Check & 0x0FFFF)==0xFFFF){
		printf("Integrité:OK -> %x\n",*Check);
	}
	else{
		printf("Integrité:Trame erronée -> %x\n",*Check);
	}
}
void free_PIP(PIP ip){
	if(!ip){return;}
	free(ip);
}
