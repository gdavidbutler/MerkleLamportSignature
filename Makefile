CFLAGS=-I. -Os

all: mls128 mls256

clobber: clean
	rm -f mls128 mls256

clean:
	rm -f mls.o

mls128: test/main.c mls.o ../rmd128/rmd128.o
	$(CC) $(CFLAGS) -DMLSHASH256=0 -I../rmd128 -o mls128 test/main.c mls.o ../rmd128/rmd128.o

mls256: test/main.c mls.o ../sha256/sha256.o
	$(CC) $(CFLAGS) -DMLSHASH256=1 -I../sha256 -o mls256 test/main.c mls.o ../sha256/sha256.o

mls.o: mls.c mls.h
	$(CC) $(CFLAGS) -c mls.c
