#include "HTTP.h"

void extract_HTTP(PHTTP http, char **line, FILE *f, int *offset, unsigned int *CheckTCP){
	char *end=0;
	unsigned int l=0,i=0;
	l=strtol(*line,&end,16);
	
	while(l!=0x20){
		*line=end;
		*offset++;
		if(*offset==16){
			*offset=0;
			assert(fgets(*line,500,f));
			}
		l=strtol(*line,&end,16);
		i++;
	}
}

char flush_data(char **line, FILE *f, unsigned int *CheckTCP){
	int i;
	while(strncmp("0000   ",*line,7)){
		if(!fgets(*line,500,f)){
			return 1;
		}
	}
	return 0;
}

void free_PHTTP(PHTTP http){
	if(!http){return;}
	free(http);
}
