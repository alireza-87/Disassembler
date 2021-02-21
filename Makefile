LIBNAME = capstone
CC = gcc

dynamic_disassembler: dynamic_disassembler.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

clean :
	rm -f dynamic_disassembler.o dynamic_disassembler
