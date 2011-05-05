CC=gcc
CFLAGS=-Wall -g -O0
all: jelvm as-jelvm jelvmtest
jelvm:	jelvmcli.o jelvm.o
jelvmtest:	jelvmtest.o jelvm.o
as-jelvm:	as-jelvm.o jelvm-as.o jelist.o
clean:
	rm -f jelvm as-jelvm jelvmtest *.o
