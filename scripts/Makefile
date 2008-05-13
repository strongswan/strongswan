all :		bin2array bin2sql id2sql key2keyid

bin2array :	bin2array.c
		gcc -o bin2array bin2array.c

bin2sql :	bin2sql.c
		gcc -o bin2sql bin2sql.c -I../src/libstrongswan -lstrongswan

id2sql :	id2sql.c
		gcc -o id2sql id2sql.c -I../src/libstrongswan -lstrongswan

key2keyid :	key2keyid.c
		gcc -o key2keyid key2keyid.c -I../src/libstrongswan -lstrongswan

clean :
		rm bin2array bin2sql id2sql key2keyid
