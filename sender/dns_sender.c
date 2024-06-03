#include "dns_sender.h"

#define NETADDR_STRLEN (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)
#define CREATE_IPV4STR(dst, src) \
    char dst[NETADDR_STRLEN];    \
    inet_ntop(AF_INET, src, dst, NETADDR_STRLEN)
#define CREATE_IPV6STR(dst, src) \
    char dst[NETADDR_STRLEN];    \
    inet_ntop(AF_INET6, src, dst, NETADDR_STRLEN)

void dns_sender__on_chunk_encoded(char *filePath, int chunkId, char *encodedData)
{
    fprintf(stderr, "[ENCD] %s %9d '%s'\n", filePath, chunkId, encodedData);
}

void on_chunk_sent(char *source, char *filePath, int chunkId, int chunkSize)
{
    fprintf(stderr, "[SENT] %s %9d %dB to %s\n", filePath, chunkId, chunkSize, source);
}

void dns_sender__on_chunk_sent(struct in_addr *dest, char *filePath, int chunkId, int chunkSize)
{
    CREATE_IPV4STR(address, dest);
    on_chunk_sent(address, filePath, chunkId, chunkSize);
}

void on_transfer_init(char *source)
{
    fprintf(stderr, "[INIT] %s\n", source);
}

void dns_sender__on_transfer_init(struct in_addr *dest)
{
    CREATE_IPV4STR(address, dest);
    on_transfer_init(address);
}

void dns_sender__on_transfer_completed(char *filePath, int fileSize)
{
    fprintf(stderr, "[CMPL] %s of %dB\n", filePath, fileSize);
}

/* *************************************TEMPLATE****************************************** */
/* ***********************************MY FUNCTIONS****************************************** */
FILE *file;

// help function for power calculation
int power(int x, int n) // x = number, n = exponent
{
    int result = 1;
    for (int i = 0; i < n; i++)
    {
        result = result * x;
    }
    return result;
}

// encoding string to base32, returns encoded string
char *encodeCalculate(char *string)
{
    /* *************************** */
    // making from incoming string a binry number
    int result[MAX_WORD];
    memset(result, 0, MAX_WORD-1);
    int m = 0;
    int j = 0;
    int len_counter = 0;
    for (int i = 7; i >= m;)
    {
        int number = string[j]; // ASCII value of char
        while (number > 0)
        {
            result[i] = number % 2;
            number = number / 2;
            i--;
            len_counter++;
        }
        if ((j + 1) == strlen(string))
            break;
        // this is for writing bin number in right order (back to front)
        m = m + 8;
        j++;
        i = m + 7;
        len_counter++;
    }
    /* *************************** */

    /* *************************** */
    // if binary string is not long enough to encode next step, this adds indexes
    int counter = 0;
    for (int t = 0; t < 101; t++)
    {
        if ((counter != 5) && (t % 5 == 0))
            counter = 0;
        if ((result[t]) == 0)
            counter = counter + 1;
        if (counter == 5)
        {
            for (int f = t; f > t - 5; f--)
                result[f] = 9; // this char is not in base32 alphabet, so it is going to fill a space at the end
            counter = 0;
        }
    }
    /* *************************** */

    /* *************************** */
    // separeted in part of 5 bits, calculating decimal value of each 5bit number
    int final[MAX_WORD];
    int i = 0;
    j = 0;
    // calculating length of result
    int nth = len_counter / 40;
    if (nth == 0)
        nth = 1;
    else if (nth % 40 > 0)
        nth++;
    nth = nth * 40 - 5;
    while (1)
    {
        if (result[i] == 9)
            final[j] = 32; // this is an extra char for filling space
        else
            final[j] = result[i] * (power(2, 4)) + result[i + 1] * (power(2, 3)) + result[i + 2] * (power(2, 2)) + result[i + 3] * (power(2, 1)) + result[i + 4] * (power(2, 0));
        if (i == nth)
            break;
        i = i + 5;
        j = j + 1;
    }
    /* *************************** */

    /* *************************** */
    // finding a right char for number. Number is an index of base32 alphabet
    nth = (nth + 5) / 5;
    char this[MAX_WORD];
    memset(this, 0, MAX_WORD);
    char base32alphabet[33] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7', '9'};
    int l;
    for (l = 0; l < nth; l++)
    {
        this[l] = base32alphabet[final[l]];
    }
    /* *************************** */

    this[l] = '\0';
    char *final_this = this;
    return final_this;
}

// making a packet header
void setPacket()
{
    // these parameters are for request dns packet
    header.id = "0100";
    header.qr = "0";
    header.qr = "0";
    header.opcode = "0000";
    header.aa = "0";
    header.tc = "0";
    header.rd = "0";
    header.z = "000";
    header.rcode = "0000";
    header.qdcount = "0001";
    header.ancount = "0000";
    header.nscount = "0000";
    header.arcount = "0000";

    question.qtype = "0001";
    question.qclass = "0001";
}

// this func adds each of header flags and params to question.all, that will be containing a whole packet
void createHeader()

{
    bzero(&header, sizeof(dns_header));
    setPacket();
    // these values are always at the start of the packet so it can be added here at first
    strcat(question.all, header.id);
    strcat(question.all, header.qr);
    strcat(question.all, header.opcode);
    strcat(question.all, header.aa);
    strcat(question.all, header.tc);
    strcat(question.all, header.rd);
    strcat(question.all, header.z);
    strcat(question.all, header.rcode);
    strcat(question.all, header.qdcount);
    strcat(question.all, header.ancount);
    strcat(question.all, header.nscount);
    strcat(question.all, header.arcount);
}

// nothing but trash
void split(char *query, char *part, char **tmp, int n)
{
    if (n == 0)
        return;
    else
    {
        char part_tmp[256];
        char query_tmp[256];
        memset(query_tmp, 0, 256);
        for (int i = 0; i < strlen(part); i++)
        {
            if (i > n - 1)
                part_tmp[i - n] = part[i];
            else
                query_tmp[i] = part[i];
        }
        query_tmp[strlen(query_tmp)] = '\0';
        strcat(query, query_tmp);
        strcpy(*tmp, part_tmp);
    }
}

// returns hex value of decimal number
char *dec2hex(int number)
{
    int rest;
    char result[2];
    int i = 1;
    if (number < 10)
    {
        result[0] = '0';
    }
    while (number > 0)
    {
        rest = number % 16;
        if (rest < 10)
            rest = rest + 48;
        else
            rest = rest + 55;

        result[i--] = rest;
        number = number / 16;
    }
    char *ret_result = result;
    return ret_result;
}

// this is first packet to send to the server with a filepath information
void sendFile(char *DST_filepath, int domain_len, struct sockaddr_in server_address, int socket_fd)
{
    char file_query[355];
    char *encoded = encodeCalculate(DST_filepath);
    int hexlen;
    char *hexstr;

    // only information in this packet for server is encoded filepath - this filepath is used on server for saving data
    strcpy(file_query, question.all);
    hexlen = strlen(encoded);
    hexstr = dec2hex(hexlen);
    strcat(file_query, "\\0x");
    strcat(file_query, hexstr);
    strcat(file_query, encoded);
    strcat(file_query, question.domain);
    sendto(socket_fd, (const char *)file_query, strlen(file_query), MSG_CONFIRM, (const struct sockaddr *)&server_address, sizeof(server_address));

    dns_sender__on_chunk_encoded(DST_filepath, 0x0100, file_query);

    dns_sender__on_chunk_sent(&server_address.sin_addr, DST_filepath, 0x0100, strlen(DST_filepath));

    dns_sender__on_transfer_completed(DST_filepath, strlen(DST_filepath));
}

void sendEnd(struct sockaddr_in server_address, int socket_fd, char *DST_filepath)
{
    char end_query[355];
    // only information in this packet for server is encoded filepath - this filepath is used on server for saving data
    strcpy(end_query, question.all);
    strcat(end_query, "\\0x08");
    strcat(end_query, "IVHEICQ9");
    strcat(end_query, question.domain);
    sendto(socket_fd, (const char *)end_query, strlen(end_query), MSG_CONFIRM, (const struct sockaddr *)&server_address, sizeof(server_address));

    dns_sender__on_chunk_encoded(DST_filepath, 0x0100, "IVHEICQ9");

    dns_sender__on_chunk_sent(&server_address.sin_addr, DST_filepath, 0x0100, 8);
}

// the second main function after main
// opens file, reads data from file, calls encode funcs, makes query parts for sending, sends it and closes file
void setName(char *SRC_filepath, int domain_len, struct sockaddr_in server_address, int socket_fd, char *DST_filepath)
{
    char word[2];        // for reading letter after letter
    char part[MAX_PART]; // max part in query
    int hexlen;          // variable of hexadecimal number of length of part of query
    char *hexstr;        // makes hexlen as a char

    /* **************************** */
    // opening file
    char cat[100] = "cat ";

    if (strcmp(SRC_filepath, "stdin"))
    {
        strcat(cat, SRC_filepath);
        file = popen(cat, "r");
        if (file == NULL)
            exit(1);
    }
    else
        file = stdin;
    /* **************************** */

    // new_max is the max number of bytes that can be sent in one packet, it depends on length of domain
    int new_max = MAX_QUERY - domain_len - 5; // 5 for /0x00 at the end
    char *query = malloc(sizeof(char) * 356); // query contains data that will be sent
    memset(query, 0, 256);
    int counter = 0; // counter of encoded data

    memset(part, 0, MAX_PART);

    /* ****************** */
    // how long is the file
    fseek(file, 0, SEEK_END);
    long int read_len = ftell(file);
    rewind(file);
    /* ****************** */
    int read_counter = 0; // counter of all read words
    int part_counter = 0; // counter of read words to fit in part

    // int temp_m = 0;
    char *encoded_part;
    while (fread(word, 1, 1, file) == 1)
    {
        strncat(part, word, 1); // every word is added to part to make a data
        read_counter++;
        part_counter++;
        if ((part_counter == 34) || (read_counter == read_len))
        {

            part_counter = 0;
            encoded_part = encodeCalculate(part);
            // query is full and cant be added more data and has to be sent
            if ((counter + 56) >= (new_max))
            {

                // this is how adding part and query works
                //  query | part
                //  question.all | query
                strcat(question.all, query);
                strcat(question.all, question.domain);

                dns_sender__on_chunk_encoded(DST_filepath, 0x0100, question.all);

                dns_sender__on_chunk_sent(&server_address.sin_addr, DST_filepath, 0x0100, counter);

                sendto(socket_fd, (const char *)question.all, strlen(question.all), MSG_CONFIRM, (const struct sockaddr *)&server_address, sizeof(server_address));

                /* ****************************** */
                // waiting for response from the server to continue
                char buffer[MAX_BUFF_LINE];
                int n;
                unsigned int len;
                n = recvfrom(socket_fd, (char *)buffer, MAX_BUFF_LINE, MSG_WAITALL, (struct sockaddr *)&server_address, &len);
                buffer[n] = '\0';
                /* ****************************** */

                // everything sent, process can start all over
                /* ****************** */
                // needed steps to initialize
                free(query);
                query = malloc(sizeof(char) * 256);
                memset(question.all, 0, strlen(question.all));
                createHeader();
                /* ****************** */

                hexlen = strlen(encoded_part);
                hexstr = dec2hex(hexlen);
                strcat(query, "\\0x");
                strcat(query, hexstr);
                strcat(query, encoded_part);
                part_counter = 0;
                memset(part, 0, MAX_PART);
                counter = 56;
            }
            else
            {

                // adding data to query
                hexlen = strlen(encoded_part);
                hexstr = dec2hex(hexlen);
                strcat(query, "\\0x");
                strcat(query, hexstr);
                strncat(query, encoded_part, hexlen);

                counter = counter + 56;
                part_counter = 0;
                // new part cant contain old already added data
                memset(part, 0, MAX_PART);
                memset(encoded_part, 0, strlen(encoded_part));
            }
        }
    }
    /* ******************************** */
    // this is the final part of the process, when the last data is sent
    encoded_part = encodeCalculate(part);

    hexlen = strlen(encoded_part);
    hexstr = dec2hex(hexlen);
    strcat(query, "\\0x");
    strcat(query, hexstr);
    strcat(query, encoded_part);
    strcat(question.all, query);

    strcat(question.all, question.domain);
    dns_sender__on_chunk_encoded(DST_filepath, 0x0100, question.all);

    dns_sender__on_chunk_sent(&server_address.sin_addr, DST_filepath, 0x0100, counter);

    sendto(socket_fd, (const char *)question.all, strlen(question.all), MSG_CONFIRM, (const struct sockaddr *)&server_address, sizeof(server_address));
    /* ******************************** */

    dns_sender__on_transfer_completed(DST_filepath, read_counter);

    free(query);
    memset(question.all, 0, strlen(question.all));
    createHeader();
}
// makes a domain string
void DNS(char *domain)
{
    // splitting www.google.com to www google com
    char delim[2] = ".";
    char *split_domain = strtok(domain, delim);
    // adding parts of domain to the main structure with their lengths
    while (split_domain != NULL)
    {
        int hexlen = strlen(split_domain);
        char *hexstr = dec2hex(hexlen);
        strcat(question.domain, "\\0x");
        strcat(question.domain, hexstr);
        strcat(question.domain, split_domain);
        split_domain = strtok(NULL, delim);
    }
    strcat(question.domain, "\\0x00");
    // finally adding last two parameters
    strcat(question.domain, question.qtype);
    strcat(question.domain, question.qclass);
}

/******************************************** ARGUMENT **************************************************/
// checking if args are okay
void argCheck(int argc, char **argv)
{
    if (argc < 3)
        exit(1);
}

// these functions bellow are made for finding arguments and checking them 
char *srcFilepath(int argc, char **argv)
{
    // 0   1  2   3     4    5
    // ./ -u  ip base  dst  src

    // 0   1    2    3
    // ./ base dst  src

    if ((strcmp(argv[1], "-u") == 0) && (argc == 6))
        return argv[5];
    else if (argc == 4)
        return argv[3];
    else
        return "stdin";
}

char *dstFilepath(int argc, char **argv)
{
    if (strcmp(argv[1], "-u") == 0)
        return argv[4];
    else
        return argv[2];
}

char *baseHost(int argc, char **argv)
{
    if (strcmp(argv[1], "-u") == 0)
        return argv[3];
    else
        return argv[1];
}

char *upstreamDnsIp(int argc, char **argv)
{
    if ((strcmp(argv[1], "-u") == 0) && (argc < 5))
        exit(1);
    if (strcmp(argv[1], "-u") == 0)
    {
        struct sockaddr_in sa;
        int result = inet_pton(AF_INET, argv[2], &(sa.sin_addr));
        if (result == 0)
            exit(1);
        else
            return argv[2];
    }
    else
    {
        FILE *file;
        file = popen("cat /etc/resolv.conf | grep \"nameserver\"", "r");
        if (file == NULL)
            exit(1);
        char *ipv4_address;
        char name[MAX_BUFF_LINE];
        fgets(name, MAX_BUFF_LINE, file);
        ipv4_address = strtok(name, " ");
        ipv4_address = strtok(NULL, "");
        pclose(file);
        return ipv4_address;
    }
}
/******************************************** ARGUMENT **************************************************/

int main(int argc, char **argv)
{
    argCheck(argc, argv);

    createHeader();

    /* ********************** BASIC STEPS **************************** */
    int socket_fd;
    char buffer[MAX_BUFF_LINE]; // buffer for reading recived data
    struct sockaddr_in server_address;

    // Creating socket file descriptor
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        exit(1);
    int server_len = sizeof(server_address);
    bzero(&server_address, server_len);

    // important variables
    char *ipv4_address = upstreamDnsIp(argc, argv);
    char *base_host = baseHost(argc, argv);
    char *DST_filepath = dstFilepath(argc, argv);
    char *SRC_filepath = srcFilepath(argc, argv);

    DNS(base_host);

    // Filling server information
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr(ipv4_address);

    dns_sender__on_transfer_init(&server_address.sin_addr);

    /* ********************** BASIC STEPS **************************** */

    int n;
    unsigned int len;
    sendFile(DST_filepath, strlen(base_host), server_address, socket_fd);
    n = recvfrom(socket_fd, (char *)buffer, MAX_BUFF_LINE, MSG_WAITALL, (struct sockaddr *)&server_address, &len);
    buffer[n] = '\0';

    setName(SRC_filepath, strlen(base_host), server_address, socket_fd, DST_filepath);

    n = recvfrom(socket_fd, (char *)buffer, MAX_BUFF_LINE, MSG_WAITALL, (struct sockaddr *)&server_address, &len);
    buffer[n] = '\0';

    sendEnd(server_address, socket_fd, DST_filepath);

    if (strcmp(SRC_filepath, "stdin"))
        pclose(file);
    close(socket_fd);
    return 0;
}
/* ******************************************************************************************* */