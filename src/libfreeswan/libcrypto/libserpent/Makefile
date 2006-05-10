CFLAGS=-O3 -fomit-frame-pointer -D__KERNEL__  -Wall $(EXTRA_CFLAGS)
INC=-I../include 
LIBOBJ=serpent.o serpent_cbc.o
BLIB=libserpent.a

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c $< -o $@

$(BLIB): $(LIBOBJ)
	/bin/rm -f $(BLIB)
	ar cr $(BLIB) $(LIBOBJ)
	-if test -s /bin/ranlib; then /bin/ranlib $(BLIB); \
	else if test -s /usr/bin/ranlib; then /usr/bin/ranlib $(BLIB); \
	else exit 0; fi; fi

test: test_main.o $(BLIB)
	$(CC) -o $@ $^ 

clean:
	rm -f *.[oa] core $(TARGET) test
