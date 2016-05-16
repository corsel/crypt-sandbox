.DEFAULT = build
LIBS = -l ssl -l crypto

build:
	gcc ${INCLUDE} -o test main.c ${LIBS}

debug: 
	gcc -g ${INCLUDE} -o test-debug main.c ${LIBS}
