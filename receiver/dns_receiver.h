#ifndef ISA22_DNS_RECEIVER_H
#define ISA22_DNS_RECEIVER_H
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
#define MAX_QUERY 255 // Bytes
#define MAX_PART 58   // Bytes

#define MAX_WORD 1000

#define TYPE_A 1     // Ipv4 address
#define TYPE_NS 2    // Nameserver
#define TYPE_CNAME 5 // canonical name
#define TYPE_SOA 6   // start of authority zone
#define TYPE_PTR 12  // domain name pointer
#define TYPE_MX 15   // mail server

typedef struct
{
    uint32_t name;   // xxxx xxxx  name of the record
    uint16_t type;   // xxxx       A, CNAME, NS, MX
    uint16_t cclass; // xxxx        stack in use protocol dependson it, IN 0001
    uint32_t ttl;    // xxxx xxxx   how long is a record valid
    uint16_t rdlen;  // xxxx        rdata length
    uint32_t rdata;  // xxxx xxxx   record length
} dns_answer;
dns_answer response;

/* **************************** MY FUNCTIONS ****************************** */
/* **************************** ISA TEMPLATE ****************************** */
/**
 * Tato metoda je volána serverem (příjemcem) při přijetí zakódovaných dat od klienta (odesílatele).
 * V případě použití více doménových jmen pro zakódování dat, volejte funkci pro každé z nich.
 *
 * @param filePath Cesta k cílovému souboru
 * @param encodedData Zakódovaná data do doménového jména (např.: "acfe2a42b.example.com")
 */
void dns_receiver__on_query_parsed(char *filePath, char *encodedData);

/**
 * Tato metoda je volána serverem (příjemcem) při příjmu části dat od klienta (odesílatele).
 *
 * @param source IPv4 adresa odesílatele
 * @param filePath Cesta k cílovému souboru
 * @param chunkId Identifikátor části dat
 * @param chunkSize Velikost části dat v bytech
 */
void dns_receiver__on_chunk_received(struct in_addr *source, char *filePath, int chunkId, int chunkSize);

/**
 * Tato metoda je volána serverem (příjemcem) při zahájení přenosu od klienta (odesílatele).
 *
 * @param source IPv4 adresa odesílatele
 */
void dns_receiver__on_transfer_init(struct in_addr *source);

/**
 * Tato metoda je volána serverem (příjemcem) při dokončení přenosu jednoho souboru od klienta (odesílatele).
 *
 * @param filePath Cesta k cílovému souboru
 * @param fileSize Celková velikost přijatého souboru v bytech
 */
void dns_receiver__on_transfer_completed(char *filePath, int fileSize);

#endif // ISA22_DNS_RECEIVER_EVENTS_H
