#ifndef ISA22_DNS_SENDER_H
#define ISA22_DNS_SENDER_H

#include <netinet/in.h>
#include <stdint.h> 
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 53
#define MAX_BUFF_LINE 1024
#define MAX_QUERY 255 //Bytes
#define MAX_PART 58 //Bytes

#define MAX_WORD 1000

#define TYPE_A 1     //Ipv4 address
#define TYPE_NS 2    //Nameserver
#define TYPE_CNAME 5 //canonical name
#define TYPE_SOA 6   //start of authority zone
#define TYPE_PTR 12  //domain name pointer
#define TYPE_MX 15   //mail server

/* ************************************** QUERY ******************************************* */
typedef struct
{
    char *id;              //xxxx
    //flags:                  //bit-mask to indicate request/response
    char *qr;     //query/response flag                               :1
    char *opcode; //pupose of message                              :4
    char *aa;     //authoritative answer                               :1
    char *tc;     //truncated message                               :1
    char *rd;     //recursion desired                               :1
    char *ra;     //recursion avaible                               :1
    char *z;      //its z! reserved                                 :3
    char *rcode;  //response code                                   :4
    // qr, opcode, aa, tc, rd, ra,  z, rcode
    // 0    0000    0   0   1   0  000  0000 = 0x0100
    char *qdcount;         //xxx1  number of questions
    char *ancount;         //xxx1  number of answers
    char *nscount;         //xxxx  number of authority records
    char *arcount;         //xxxx  number of additional records
} dns_header;

typedef struct
{
    char header[250];
    char all[455];        //xxxx xxxx xxxx xxxx xxxx xxxx 00  pointer to the domain name in memory
    char domain[256];        //xxxx xxxx xxxx xxxx xxxx xxxx 00  pointer to the domain name in memory 
    char* qtype;    //xxxx 1=A QTYPE
    char* qclass;   //xxxx 1=IN QCLASS
} dns_question;

/* ************************************** QUERY ******************************************* */
dns_header header;
dns_question question;

/* ***************************************************************************************** */

/**
 * Tato metoda je volána klientem (odesílatelem) při zakódování části dat do doménového jména.
 * V případě použití více doménových jmen pro zakódování dat, volejte funkci pro každé z nich.
 *
 * @param filePath Cesta k cílovému souboru
 * @param chunkId Identifikátor části dat
 * @param encodedData Zakódovaná data do doménového jména (např.: "acfe2a42b.example.com")
 */
void dns_sender__on_chunk_encoded(char *filePath, int chunkId, char *encodedData);

/**
 * Tato metoda je volána klientem (odesílatelem) při odeslání části dat serveru (příjemci).
 *
 * @param dest IPv4 adresa příjemce
 * @param filePath Cesta k cílovému souboru (relativní na straně příjemce)
 * @param chunkId Identifikátor části dat
 * @param chunkSize Velikost části dat v bytech
 */
void dns_sender__on_chunk_sent(struct in_addr *dest, char *filePath, int chunkId, int chunkSize);

/**
 * Tato metoda je volána klientem (odesílatelem) při zahájení přenosu serveru (příjemci).
 *
 * @param dest IPv4 adresa příjemce
 */
void dns_sender__on_transfer_init(struct in_addr *dest);

/**
 * Tato metoda je volána klientem (odesílatelem) při dokončení přenosu jednoho souboru serveru (příjemci).
 *
 * @param filePath Cesta k cílovému souboru
 * @param fileSize Celková velikost přijatého souboru v bytech
 */
void dns_sender__on_transfer_completed( char *filePath, int fileSize);

#endif //ISA22_DNS_SENDER_EVENTS_H
