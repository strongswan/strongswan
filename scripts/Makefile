all :		bin2array bin2sql id2sql

bin2array :	bin2array.c
		gcc -o bin2array bin2array.c

bin2sql :	bin2sql.c
		gcc -o bin2sql bin2sql.c -I../src/libstrongswan -lstrongswan

id2sql :	id2sql.c
		gcc -o id2sql id2sql.c -I../src/libstrongswan -lstrongswan

clean :
		rm bin2array bin2sql id2sql
