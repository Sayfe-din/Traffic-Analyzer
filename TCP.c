#include "TCP.h"

int extract_ALL_TCP(PTCP tcp, char **line, FILE *f, char offset, unsigned int *CheckTCP){
	assert(f);
	char *end=0;
	int null=0;
	
	
	
	
	
	if(offset==0){
		
		end=*line;
		
		tcp->SrcPort=strtol(end,line,16) << 8;
		tcp->SrcPort+=strtol(*line,&end,16);
		if(*line==end){abort_format();}

		tcp->DestPort=(strtol(end,line,16) << 8);
		tcp->DestPort+=strtol(*line,&end,16);

		if(*line==end){abort_format();}
		
		tcp->SEQN=strtol(end,line,16) << 24;
		tcp->SEQN+=(strtol(*line,&end,16) << 16);
		
		
		tcp->SEQN+=(strtol(end,line,16) << 8);
		tcp->SEQN+=strtol(*line,&end,16);
		

		if(*line==end){abort_format();}
		
		tcp->ACKN=strtol(end,line,16) << 24;
		tcp->ACKN+=(strtol(*line,&end,16) << 16);
		
		tcp->ACKN+=(strtol(end,line,16) << 8);
		tcp->ACKN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}

		tcp->THL=strtol(end,line,16) & 0xF0;
		tcp->THL=tcp->THL >> 4;

		if(*line==end){abort_format();}

		null=strtol(*line,&end,16);
		tcp->URG=(null & 0x20) >> 5;
		tcp->ACK=(null & 0x10) >> 4;
		tcp->PSH=(null & 0x08) >> 3;
		tcp->RST=(null & 0x04) >> 2;
		tcp->SYN=(null & 0x02) >> 1;
		tcp->FIN=null & 0x01;
		
		if(*line==end){abort_format();}
		
		assert(fgets(*line,500,f));
		null=strtol(*line,&end,16);
		end=end+2;
		
		tcp->WIN=strtol(end,line,16) << 8;
		tcp->WIN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}

		tcp->Checksum=strtol(end,line,16) << 8;
		tcp->Checksum+=strtol(*line,&end,16);

		if(*line==end){abort_format();}

		tcp->Urgent=strtol(end,line,16) << 8;
		tcp->Urgent+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}
	}
	
	
	
	
	
	
	else if(offset==1){
		
		end=*line;
		
		tcp->SrcPort=strtol(end,line,16) << 8;
		tcp->SrcPort+=strtol(*line,&end,16);
		if(*line==end){abort_format();}

		tcp->DestPort=(strtol(end,line,16) << 8);
		tcp->DestPort+=strtol(*line,&end,16);

		if(*line==end){abort_format();}
		
		tcp->SEQN=strtol(end,line,16) << 24;
		tcp->SEQN+=(strtol(*line,&end,16) << 16);
		
		tcp->SEQN+=(strtol(end,line,16) << 8);
		tcp->SEQN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}
		
		tcp->ACKN=strtol(end,line,16) << 24;
		tcp->ACKN+=(strtol(*line,&end,16) << 16);
		
		assert(fgets(*line,500,f));
		null=strtol(*line,&end,16);
		end=end+2;
		
		tcp->ACKN+=(strtol(end,line,16) << 8);
		tcp->ACKN+=strtol(*line,&end,16);
		
		
		if(*line==end){abort_format();}

		tcp->THL=strtol(end,line,16) & 0xF0;
		tcp->THL=tcp->THL >> 4;

		if(*line==end){abort_format();}

		null=strtol(*line,&end,16);
		tcp->URG=(null & 0x20) >> 5;
		tcp->ACK=(null & 0x10) >> 4;
		tcp->PSH=(null & 0x08) >> 3;
		tcp->RST=(null & 0x04) >> 2;
		tcp->SYN=(null & 0x02) >> 1;
		tcp->FIN=null & 0x01;

		if(*line==end){abort_format();}
		
		tcp->WIN=strtol(end,line,16) << 8;
		tcp->WIN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}

		tcp->Checksum=strtol(end,line,16) << 8;
		tcp->Checksum+=strtol(*line,&end,16);

		if(*line==end){abort_format();}

		tcp->Urgent=strtol(end,line,16) << 8;
		tcp->Urgent+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}
	}
	
	
	
	
	
	else if(offset==2){
		
		end=*line;
		
		tcp->SrcPort=strtol(end,line,16) << 8;
		tcp->SrcPort+=strtol(*line,&end,16);
		if(*line==end){abort_format();}

		tcp->DestPort=(strtol(end,line,16) << 8);
		tcp->DestPort+=strtol(*line,&end,16);

		if(*line==end){abort_format();}
		
		tcp->SEQN=strtol(end,line,16) << 24;
		tcp->SEQN+=(strtol(*line,&end,16) << 16);
		
		assert(fgets(*line,500,f));
		null=strtol(*line,&end,16);
		end=end+2;
		
		tcp->SEQN+=(strtol(end,line,16) << 8);
		tcp->SEQN+=strtol(*line,&end,16);

		if(*line==end){abort_format();}
		
		tcp->ACKN=strtol(end,line,16) << 24;
		tcp->ACKN+=(strtol(*line,&end,16) << 16);
		
		tcp->ACKN+=(strtol(end,line,16) << 8);
		tcp->ACKN+=strtol(*line,&end,16);
		
		
		if(*line==end){abort_format();}

		tcp->THL=strtol(end,line,16) & 0xF0;
		tcp->THL=tcp->THL >> 4;

		if(*line==end){abort_format();}

		null=strtol(*line,&end,16);
		tcp->URG=(null & 0x20) >> 5;
		tcp->ACK=(null & 0x10) >> 4;
		tcp->PSH=(null & 0x08) >> 3;
		tcp->RST=(null & 0x04) >> 2;
		tcp->SYN=(null & 0x02) >> 1;
		tcp->FIN=null & 0x01;

		if(*line==end){abort_format();}
		
		tcp->WIN=strtol(end,line,16) << 8;
		tcp->WIN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}

		tcp->Checksum=strtol(end,line,16) << 8;
		tcp->Checksum+=strtol(*line,&end,16);

		if(*line==end){abort_format();}

		tcp->Urgent=strtol(end,line,16) << 8;
		tcp->Urgent+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}
	}
	
	
	
	
	
	else if(offset==3){
		
		end=*line;
		
		tcp->SrcPort=strtol(end,line,16) << 8;
		tcp->SrcPort+=strtol(*line,&end,16);
		if(*line==end){abort_format();}

		if(*line==end){abort_format();}

		assert(fgets(*line,500,f));
		null=strtol(*line,&end,16);
		end=end+2;

		tcp->DestPort=(strtol(end,line,16) << 8);
		tcp->DestPort+=strtol(*line,&end,16);

		if(*line==end){abort_format();}

		if(*line==end){abort_format();}
		
		tcp->SEQN=strtol(end,line,16) << 24;
		tcp->SEQN+=(strtol(*line,&end,16) << 16);
		
		tcp->SEQN+=(strtol(end,line,16) << 8);
		tcp->SEQN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}
		
		tcp->ACKN=strtol(end,line,16) << 24;
		tcp->ACKN+=(strtol(*line,&end,16) << 16);
		
		tcp->ACKN+=(strtol(end,line,16) << 8);
		tcp->ACKN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}

		tcp->THL=strtol(end,line,16) & 0xF0;
		tcp->THL=tcp->THL >> 4;

		if(*line==end){abort_format();}

		null=strtol(*line,&end,16);
		tcp->URG=(null & 0x20) >> 5;
		tcp->ACK=(null & 0x10) >> 4;
		tcp->PSH=(null & 0x08) >> 3;
		tcp->RST=(null & 0x04) >> 2;
		tcp->SYN=(null & 0x02) >> 1;
		tcp->FIN=null & 0x01;
		

		if(*line==end){abort_format();}
		
		tcp->WIN=strtol(end,line,16) << 8;
		tcp->WIN+=strtol(*line,&end,16);
		
		if(*line==end){abort_format();}

		tcp->Checksum=strtol(end,line,16) << 8;
		tcp->Checksum+=strtol(*line,&end,16);

		if(*line==end){abort_format();}

		tcp->Urgent=strtol(end,line,16) << 8;
		tcp->Urgent+=strtol(*line,&end,16);
		
		
		if(*line==end){abort_format();}
	}
	//Calcule du Checksum de l'entete TCP
	*CheckTCP+=tcp->SrcPort;
	*CheckTCP+=tcp->DestPort;
	*CheckTCP+=(tcp->SEQN >> 16);
	*CheckTCP+=(tcp->SEQN & 0x0000FFFF);
	*CheckTCP+=(tcp->ACKN >> 16);
	*CheckTCP+=(tcp->ACKN & 0x0000FFFF);
	*CheckTCP+=(tcp->THL << 12);
	*CheckTCP+=null;               //Flags
	*CheckTCP+=tcp->WIN;
	*CheckTCP+=tcp->Checksum;
	*CheckTCP+=tcp->Urgent;
	
	offset=offset*4+4+2; //Calcul de l'offset relatif au premier octet de la ligne dû aux options IP offset*4+2 et l'entete TCP 4 (20-16) 
	offset=offset%16;
	
	
	
	
	
	
	
	
	
	
	null=tcp->THL-5;

	while(null--){//Passage sur les Options
		int unused=strtol(end,line,16) << 8;
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		unused+=strtol(*line,&end,16);
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		*CheckTCP+=unused;
		unused=strtol(end,line,16) << 8;
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		unused=strtol(*line,&end,16);
		offset++;
		if(offset==16){
			assert(fgets(*line,500,f));
			end=*line+6;
			*line=end;
			offset=0;
			}
		*CheckTCP+=unused;
		
		if(*line==end){abort_format();}
	}
	*line=end;
	null=tcp->THL-5;
	
	return null%4;
}

void fprint_TCP(PTCP tcp, FILE *file, unsigned int tramenum){
	fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%u\t\t------------------------------->\t\t%u\t\t\t\t\t\t\t\tTCP: Seq=%u Ack=%u,Window=%u\n",tramenum,tcp->SrcPort,tcp->DestPort,tcp->SEQN,tcp->ACKN,tcp->WIN);
}

void fprint_reverse_TCP(PTCP tcp, FILE *file, unsigned int tramenum){

	fprintf(file,"%u\t\t\t\t\t\t\t\t\t\t%u\t\t<-------------------------------\t\t%u\t\t\t\t\t\t\t\tTCP: Seq=%u Ack=%u,Window=%u\n",tramenum,tcp->DestPort,tcp->SrcPort,tcp->SEQN,tcp->ACKN,tcp->WIN);
	
}

void print_TCP(PTCP tcp){
		//Affichage  des champs de l'entete TCP dans le terminal
		printf("\t\tTCP Segment:\n\t\t\tSource port number:%04x\n\t\t\tDestination port number:%04x\n\t\t\tSequence number:%08x\n\t\t\tAcknowledgment number:%08x\n\t\t\tTHL:%02x\n\t\t\tURG:%d , ACK:%d\n\t\t\tPSH:%d , RST:%d\n\t\t\tSYN:%d , FIN:%d\n\t\t\tWIN:%04x\n\t\t\tChecksum:%04x\n\t\t\tUrgent Pointer:%04x\n",tcp->SrcPort,tcp->DestPort,tcp->SEQN,tcp->ACKN,tcp->THL,tcp->URG,tcp->ACK,tcp->PSH,tcp->RST,tcp->SYN,tcp->FIN,tcp->WIN,tcp->Checksum,tcp->Urgent);
}

void free_PTCP(PTCP tcp){
	if(!tcp){return;}
	free(tcp);
	
	return;
}

