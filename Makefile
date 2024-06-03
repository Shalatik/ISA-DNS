# Projekt: VUT FIT ISA projekt DNS tunelovani
# Autor: Simona Ceskova xcesko00
# Datum: 14.11.2022
	
CC = gcc
CFLAGS = -std=gnu99 -Wall -g
H_FILE = dns_receiver.h dns_sender.h
OBJECTS =  dns_receiver.o dns_sender.o 
TARGET = dns_receiver dns_sender

all: clean $(TARGET)

&(TARGET): $(OBJECTS) $(H_FILE)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

%.o: %.c $(H_FILE)
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean all

clean:
	rm -f $(OBJECTS) $(TARGET) *~
