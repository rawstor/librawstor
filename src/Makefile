CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Werror

DEPS = rawstor.h

OBJ = rawstor.o 


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

%.a: $(OBJ)
	ar rcs $@ $<

all: librawstor.a

clean:
	rm -f *.o librawstor.a

.PHONY: all clean
