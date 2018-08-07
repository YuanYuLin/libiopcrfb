
TARGET = libiopcrfb.so

#CFLAGS += -I$(SDKSTAGE)/usr/include/libbdb
#CFLAGS += -I$(SDKSTAGE)/usr/include/libtokyocabinet
CFLAGS += -I$(SDKSTAGE)/usr/include/libiopcmisc
CFLAGS += -I$(SDKSTAGE)/usr/include/libiopccmd
CFLAGS += -I$(SDKSTAGE)/usr/include/libz
CFLAGS += -I$(SDKSTAGE)/usr/include/platform
CFLAGS += -I$(SDKSTAGE)/usr/include/
CFLAGS += -I./include/
CFLAGS += 

LDFLAGS += -L$(SDKSTAGE)/lib/ 
LDFLAGS += -L$(SDKSTAGE)/usr/lib/ 
LDFLAGS += -lc -lpthread -ldl
#LDFLAGS += -ldb 

SRC = 

SRC += ops_rfb.c

include Makefile.include.lib
