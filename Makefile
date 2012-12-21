CC = gcc

LIBS = -lgmp -lstdc++


all: my_rsakeygen rsa_engine

my_rsakeygen: my_rsakeygen.o 
	${CC} -o my_rsakeygen my_rsakeygen.o ${LIBS}
my_rsakeygen.o: my_rsakeygen.cpp
	${CC} -c my_rsakeygen.cpp

rsa_engine: rsa_engine.o 
	${CC} -o rsa_engine rsa_engine.o ${LIBS}
rsa_engine.o: rsa_engine.cpp
	${CC} -c rsa_engine.cpp

clean:
	rm my_rsakeygen my_rsakeygen.o rsa_engine rsa_engine.o *.der *.enc *.dec
