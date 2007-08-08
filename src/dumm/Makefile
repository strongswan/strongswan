
dumm:	dumm.c dumm.h guest.c guest.h iface.c iface.h bridge.c bridge.h mconsole.c mconsole.h cowfs.h cowfs.c main.c
	gcc -o dumm dumm.c guest.c iface.c bridge.c mconsole.c cowfs.c main.c `pkg-config fuse --cflags --libs` -ledit -lbridge -lpthread -lstrongswan -I../libstrongswan/ -g -O2 -Wall -Wno-format -Wno-strict-aliasing
