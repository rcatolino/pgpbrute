CC:=gcc
LD:=gcc

CCFLAGS:=-Wall -g -std=gnu99
LDFLAGS:=-Wall -g

INCLUDES:=-I/usr/include/glib-2.0/ -I/usr/lib/glib-2.0/include/

DEFINES:=-D DEBUG

EXE:=crack

LIBS:=-lglib-2.0 -lrt
OBJ:=crack.o pgp.o

.PHONY: clean

$(EXE): $(OBJ)
	@echo building $@
	$(LD) -o $(EXE) $(LDFLAGS) $(OBJ) $(LIBS)
	@echo done

%.o : %.c *.h
	@echo building $@ ...
	$(CC) $(CCFLAGS) -c $(DEFINES) $(INCLUDES) $<
	@echo done

clean:
	@echo -n cleaning repository...
	-@rm -rf *.o
	-@rm -rf *.so*
	-@rm -rf *~
	@echo cleaned.
