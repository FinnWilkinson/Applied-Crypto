# Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
#
# Use of this source code is restricted per the CC BY-NC-ND license, a copy of 
# which can be found via http://creativecommons.org (and should be included as 
# LICENSE.txt within the associated archive or repository).

SOURCES = $(wildcard *.c)
TARGETS = $(patsubst %.c, %, ${SOURCES})

${TARGETS} : % : %.c %.h
	@gcc -Wall -std=gnu99 -O3 -o ${@} $(filter %.c, ${^}) -lgmp -lcrypto

all   :             ${TARGETS}

clean :
	@rm -f core ${TARGETS} *.pyo *.pyc
