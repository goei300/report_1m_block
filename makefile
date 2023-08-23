LDLIBS= -lnetfilter_queue

all: nfqnl_test dummydrop

nfqnl_test.o: nfqnl_test.c

dummydrop.o: dummydrop.c

nfqnl_test: nfqnl_test.o
dummydrop: dummydrop.o

clean:
	rm -f nfqnl_test
	rm -f dummydrop
