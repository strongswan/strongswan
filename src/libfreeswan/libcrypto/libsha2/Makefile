CFLAGS=-O3 -fomit-frame-pointer -I../include $(EXTRA_CFLAGS)

LIBOBJ := hmac_sha2.o sha2.o

BLIB := libsha2.a

.S.o:
	$(CC) $(AFLAGS) -c $< -o $@

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
