fic ?=""
save ?=""
CC =gcc-10 -Wall --pedantic -o 

help:
	@echo -e 'Usage:\n\tmake -B exec fic=file_name save=file_to_save_exchanges_in_trace fil="filter_1 filter_2"'

%.o: %.c
	@$(CC) $@ -c $^

wirecatfish: main.o Ethernet.o IP.o TCP.o HTTP.o
	@$(CC) $@ $^
	@rm -f *.o

exec: wirecatfish
	./wirecatfish $(fic) $(save)

clean:
	rm -f *.o wirecatfish

