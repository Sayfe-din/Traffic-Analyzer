#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "main.h"

void free_CellFrame(CellFrame *cframe){
	assert(cframe);
	CellFrame *tmp=cframe->next;
	while(tmp){
		free_PEthernet(cframe->eth);
		free_PIP(cframe->ip);
		free_PTCP(cframe->tcp);
		free_PHTTP(cframe->http);
		free(cframe);
		cframe=tmp;
		tmp=tmp->next;
	}
	free_PEthernet(cframe->eth);
	free_PIP(cframe->ip);
	free_PTCP(cframe->tcp);
	free_PHTTP(cframe->http);
	free(cframe);
	
	return;
}

extern void abort_format(){
	printf("Mauvais format de fichier\n");
}

void fprint_IP(CellFrame *tmp, FILE *file, unsigned int tramenum){
	fprintf(file,"%u\t\t\t\t\t\t\t\t\t%u.%u.%u.%u\t------------------------------->\t%u.%u.%u.%u\t\t\t\t\t\t\tIPv4: Protocol:%02x (Unknown)\n",tramenum,(tmp->ip->IPS) >>24,(tmp->ip->IPS & 0x00FFFFFF) >>16,(tmp->ip->IPS & 0x0000FFFF) >>8,(tmp->ip->IPS & 0x000000FF),(tmp->ip->IPD) >>24,(tmp->ip->IPD & 0x00FFFFFF) >>16,(tmp->ip->IPD & 0x0000FFFF) >>8,(tmp->ip->IPD & 0x000000FF),tmp->ip->Proto);
}

void fprint_reverse_IP(CellFrame *tmp, FILE *file, unsigned int tramenum){
	fprintf(file,"%u\t\t\t\t\t\t\t\t\t%u.%u.%u.%u\t <-------------------------------\t%u.%u.%u.%u\t\t\t\t\t\t\tIPv4: Protocol:%02x (Unknown)\n",tramenum,(tmp->ip->IPD) >>24,(tmp->ip->IPD & 0x00FFFFFF) >>16,(tmp->ip->IPD & 0x0000FFFF) >>8,(tmp->ip->IPD & 0x000000FF),(tmp->ip->IPS) >>24,(tmp->ip->IPS & 0x00FFFFFF) >>16,(tmp->ip->IPS & 0x0000FFFF) >>8,(tmp->ip->IPS & 0x000000FF),tmp->ip->Proto);
}
void fprint_HTTP(CellFrame *tmp, FILE *file, unsigned int tramenum){
	
	fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%u\t\t------------------------------->\t\t%u\t\t\t\t\t\t\t\tHTTP:%s%s\n",tramenum,tmp->tcp->SrcPort,tmp->tcp->DestPort,tmp->http->Method,tmp->http->Version);
	
}

void fprint_reverse_HTTP(CellFrame *tmp, FILE *file, unsigned int tramenum){
	fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%u\t\t<-------------------------------\t\t%u\t\t\t\t\t\t\t\tHTTP:%s%s\n",tramenum,tmp->tcp->DestPort,tmp->tcp->SrcPort,tmp->http->Method,tmp->http->Version);
}

void save_exchanges(CellFrame *f, char *name){
	assert(f);
	FILE *file=fopen(name,"w");
	assert(file);
	unsigned int i=2,first=f->ip->IPS;
	CellFrame *tmp=f;
	fprintf(file,"N°                                                               Exchange                                                                   Comment\n");
	if(tmp->http){
		fprint_HTTP(tmp,file,1);
	}
	else if(tmp->tcp){
		
		fprint_TCP(tmp->tcp,file,1);
	}
	else if(tmp->ip){
	
		fprint_IP(tmp,file,1);
	}
	else if(tmp->eth){
		fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%02x:%02x:%02x:%02x:%02x:%02x\t\t------------------------------->\t\t%02x:%02x:%02x:%02x:%02x:%02x\t\t\t\t\t\t\t\tFrame: Protocol:%02x%02x\n",1,tmp->eth->MACdest[0],tmp->eth->MACdest[1],tmp->eth->MACdest[2],tmp->eth->MACdest[3],tmp->eth->MACdest[4],tmp->eth->MACdest[5],tmp->eth->MACsrc[0],tmp->eth->MACsrc[1],tmp->eth->MACsrc[2],tmp->eth->MACsrc[3],tmp->eth->MACsrc[4],tmp->eth->MACsrc[5],tmp->eth->Proto[0],tmp->eth->Proto[1]);
	}
	tmp=f->next;
	while(tmp){
		if(tmp->ip && f->ip){
			if(tmp->ip->IPD==first){
				if(tmp->http){
					fprint_reverse_HTTP(tmp,file,i);
				}
				else if(tmp->tcp){
					
					fprint_reverse_TCP(tmp->tcp,file,i);
				}
				else if(tmp->ip){
				
					fprint_reverse_IP(tmp,file,i);
				}
				else if(tmp->eth){
					fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%02x:%02x:%02x:%02x:%02x:%02x\t\t------------------------------->\t\t%02x:%02x:%02x:%02x:%02x:%02x\t\t\t\t\t\t\t\tFrame: Protocol:%02x%02x\n",i,tmp->eth->MACsrc[0],tmp->eth->MACsrc[1],tmp->eth->MACsrc[2],tmp->eth->MACsrc[3],tmp->eth->MACsrc[4],tmp->eth->MACsrc[5],tmp->eth->MACdest[0],tmp->eth->MACdest[1],tmp->eth->MACdest[2],tmp->eth->MACdest[3],tmp->eth->MACdest[4],tmp->eth->MACdest[5],tmp->eth->Proto[0],tmp->eth->Proto[1]);
				}
			}
			else{
				if(tmp->http){
					fprint_HTTP(tmp,file,i);
				}
				else if(tmp->tcp){
					
					fprint_TCP(tmp->tcp,file,i);
				}
				else if(tmp->ip){
				
					fprint_IP(tmp,file,i);
				}
				else if(tmp->eth){
					fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%02x:%02x:%02x:%02x:%02x:%02x\t\t------------------------------->\t\t%02x:%02x:%02x:%02x:%02x:%02x\t\t\t\t\t\t\t\tFrame: Protocol:%02x%02x\n",i,tmp->eth->MACdest[0],tmp->eth->MACdest[1],tmp->eth->MACdest[2],tmp->eth->MACdest[3],tmp->eth->MACdest[4],tmp->eth->MACdest[5],tmp->eth->MACsrc[0],tmp->eth->MACsrc[1],tmp->eth->MACsrc[2],tmp->eth->MACsrc[3],tmp->eth->MACsrc[4],tmp->eth->MACsrc[5],tmp->eth->Proto[0],tmp->eth->Proto[1]);}
			}
		}
		f=f->next;
		tmp=f->next;
		i++;
	}
	return;
}

void filter(CellFrame *f,char *fil){}

int main(int argc, char **argv){
	FILE *f=fopen(argv[1],"r");
	assert(f);
	char *s=malloc(sizeof(char)*501),*end=s,*end2=0;
	fgets(s,500,f);
	
	int iteration=strtol(s,NULL,16);
	CellFrame *frame=malloc(sizeof(CellFrame)),*frames=frame;
	while(!iteration){
		PEthernet eth=malloc(sizeof(Ethernet));
		
		
		int i=extract_MAC(eth,&s);
		i=extract_PROTO(eth,&s);
		
		
		unsigned int CheckIP=0,CheckTCP=0;
		
		print_ETHERNET(eth);
		
		//Protocol IP
		if(i=='4'){
			PIP ip=malloc(sizeof(IP));
			i=extract_ALL_IP(ip,&s,f,&CheckIP,&CheckTCP);
			print_IP(ip,&CheckIP);
			
			//Protocol TCP
			if(ip->Proto==0x06){
				PTCP tcp=malloc(sizeof(TCP));
				
				
				i=extract_ALL_TCP(tcp,&s,f,i,&CheckTCP)*4+2;
				strtol(s,&end2,16);
				
				if(s!=end2){
					PHTTP http=malloc(sizeof(HTTP));
					frame->http=http;
					extract_HTTP(http,&s,f,&i,&CheckTCP);
				}
				iteration=flush_data(&s,f,&CheckTCP);
				CheckTCP+=ip->Length-(ip->IHL*4);
				CheckTCP+=(CheckTCP >> 16);
				print_TCP(tcp);
				frame->tcp=tcp;
			}
			else{
				iteration=flush_data(&s,f,&CheckTCP);
			}
			frame->ip=ip;
		}
		else{
			iteration=flush_data(&s,f,&CheckTCP);
		}
		frame->eth=eth;
		
		frame->next=malloc(sizeof(CellFrame));
		frame=frame->next;
	}
	filter(frames,argv[2]);
	save_exchanges(frames,argv[2]);
	free_CellFrame(frames);
	free(end);
	return 0;
}

