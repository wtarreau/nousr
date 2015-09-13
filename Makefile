CFLAGS  = -O3 -fPIE
LDFLAGS = -pie -fPIE

all: nousr.so

%.so: %.o
	$(CC) $(LDFLAGS) -o $@ $< -ldl

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.so *.o *~ core

