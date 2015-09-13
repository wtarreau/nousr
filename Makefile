CFLAGS  = -O3 -fPIC
LDFLAGS = -shared -fPIC

all: nousr.so

%.so: %.o
	$(CC) $(LDFLAGS) -o $@ $< -ldl

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.so *.o *~ core

