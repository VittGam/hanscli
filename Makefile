LDFLAGS =
CFLAGS = -g
GCC = gcc

all: hanscli

hanscli: main.c sha1.c libsha1.h
	$(GCC) -o hanscli main.c sha1.c $(CFLAGS) $(LDFLAGS)

clean:
	rm -f hanscli
