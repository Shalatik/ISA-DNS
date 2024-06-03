#include "dns_receiver.h"

#define NETADDR_STRLEN (INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN)
#define CREATE_IPV4STR(dst, src) \
    char dst[NETADDR_STRLEN];    \
    inet_ntop(AF_INET, src, dst, NETADDR_STRLEN)
#define CREATE_IPV6STR(dst, src) \
    char dst[NETADDR_STRLEN];    \
    inet_ntop(AF_INET6, src, dst, NETADDR_STRLEN)

void dns_receiver__on_query_parsed(char *filePath, char *encodedData)
{
    fprintf(stderr, "[PARS] %s '%s'\n", filePath, encodedData);
}

void on_chunk_received(char *source, char *filePath, int chunkId, int chunkSize)
{
    fprintf(stderr, "[RECV] %s %9d %dB from %s\n", filePath, chunkId, chunkSize, source);
}

void dns_receiver__on_chunk_received(struct in_addr *source, char *filePath, int chunkId, int chunkSize)
{
    CREATE_IPV4STR(address, source);
    on_chunk_received(address, filePath, chunkId, chunkSize);
}

void on_transfer_init(char *source)
{
    fprintf(stderr, "[INIT] %s\n", source);
}

void dns_receiver__on_transfer_init(struct in_addr *source)
{
    CREATE_IPV4STR(address, source);
    on_transfer_init(address);
}

void dns_receiver__on_transfer_completed(char *filePath, int fileSize)
{
    fprintf(stderr, "[CMPL] %s of %dB\n", filePath, fileSize);
}

/* ************************************MY IMPLEMENTATION******************************************* */
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

// function for decoding incomming string of data
char *decodeCalculate(char *string, char *split2)
{
    // in this part is checking if incomming string is length that does not need to me decoded
    int len = strlen(string); // 8 16 24 32 40 ...
    if (len <= 4)
        return "wrongdecodereturn";
    int corrC = 0;
    if (len == strlen(split2) + 4)
    {
        for (int i = 0; i < strlen(split2); i++) // \0x00
        {
            if (string[i + 4] == split2[i])
                corrC++;
        }
        if (corrC == strlen(split2))
            return "wrongdecodereturn";
    }

    // chars are transformed into their index value
    int cnt9 = 0;
    char base32alphabet[32] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '2', '3', '4', '5', '6', '7'};
    int numbers[strlen(string) - 4];

    for (int i = 4; i < len; i++) // when string comes it has form of 0xXX..., first 4 chars can be ingnored
    {
        if (string[i] == '9')
        {
            cnt9++;
            numbers[i - 4] = 0;
        }
        else
        {
            for (int j = 0; j < 32; j++)
            {
                if (base32alphabet[j] == string[i])
                {
                    numbers[i - 4] = j;
                    break;
                }
            }
        }
    }
    len = len - 4; // 8 16 24 32 40 ...
    len = len * 5;

    // from each number is gonna be binary number of 5 digits, this is basicaly dec to binary function part
    int result[len];
    int m = 0;
    int j = 0;
    for (int h = 0; h < len; h++)
        result[h] = 0;

    for (int i = 4; i >= m;)
    {
        if ((j) >= (len / 5))
            break;
        int number = numbers[j]; // 0C 1a 2t
        while (number > 0)
        {
            result[i] = number % 2;
            number = number / 2;
            i--;
        }
        number = 0;
        m = m + 5;
        j++;
        i = m + 4;
    }
    int final_len = len / 8;
    int final[final_len];
    for (int q = 0; q < final_len; q++)
        final[q] = 0;

    int i = 0;
    j = 0;
    // and then these parts of 5 bin digits are separeted into parts of 8 digits and transformed into decimal
    while (j <= final_len)
    {
        final[j] = result[i] * (power(2, 7)) + result[i + 1] * (power(2, 6)) + result[i + 2] * (power(2, 5)) + result[i + 3] * (power(2, 4)) + result[i + 4] * (power(2, 3)) + result[i + 5] * (power(2, 2)) + result[i + 6] * (power(2, 1)) + result[i + 7] * (power(2, 0));

        i = i + 8;
        j++;
    }

    // here is transform o chars from ints
    char *temp_a = malloc(sizeof(char) * final_len);
    memset(temp_a, 0, final_len);
    for (int l = 0; l < final_len; l++)
        temp_a[l] = final[l];
    // temp_a is decoded string
    return temp_a;
}

void argCheck(int argc, char **argv)
{
    if (argc < 2)
        exit(1);
}

// writes data stored in string into a file
void saveToFile(char *string)
{
    if (file == NULL)
        exit(1);
    fprintf(file, "%s", string);
}

void extractPacket(char buffer[MAX_BUFF_LINE], char *base_host, char *toSend, int *size_counter)
{
    char del2[3] = "."; // \0x00 etc... does not belong into a file with data
    char *split2 = strtok(base_host, del2);

    char delim[3] = "\\"; // \0x00 etc... does not belong into a file with data
    char *splitted = strtok(buffer, delim);
    char *decoded_word;

    int bool_counter = 0; // first part before \ contains flags, params, ...
    while (splitted != NULL)
    {
        if (bool_counter)
        {
            strcat(toSend, splitted);
            decoded_word = decodeCalculate(splitted, split2);
            if (strcmp(decoded_word, "wrongdecodereturn") == 0)
                break;
            *size_counter = *size_counter + strlen(decoded_word);
            saveToFile(decoded_word);
        }

        splitted = strtok(NULL, delim);
        if (bool_counter)
            free(decoded_word);
        bool_counter = 1;
    }
    while (splitted != NULL)
    {
        strcat(toSend, splitted);
        splitted = strtok(NULL, delim);
    }
}

// takes first packet what is always a file packet, contains information about filepath
char *extractFirstPacket(char buffer[MAX_BUFF_LINE], char *toSend, int *first_size)
{
    char delim[3] = "\\";
    char *splitted = strtok(buffer, delim);
    splitted = strtok(NULL, delim); // only using query
    char *decoded_word;
    decoded_word = decodeCalculate(splitted, "thisdoesnotmatteratall");

    while (splitted != NULL)
    {
        strcat(toSend, splitted);
        splitted = strtok(NULL, delim);
    }
    *first_size = strlen(decoded_word);
    //decoded_word is decoded name of file
    return decoded_word;
}

int main(int argc, char **argv)
{
    argCheck(argc, argv);
    char *base_host = argv[1];
    char *DST_dirpath = argv[2];
    /* ************************ BASIC STEPS *********************** */
    int socket_fd;
    char buffer[MAX_BUFF_LINE];
    struct sockaddr_in server_address, client_address;

    // Creating socket file descriptor
    if ((socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(1);
    }

    unsigned int server_len = sizeof(server_address);
    unsigned int client_len = sizeof(client_address);

    bzero(&server_address, server_len);
    bzero(&client_address, client_len);

    // Filling server information
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT); // FIXME: port 53

    // Bind the socket with the server address
    if (bind(socket_fd, (const struct sockaddr *)&server_address, server_len) < 0)
        exit(1);

    int n;
    client_len = sizeof(client_address);
    /* ************************ BASIC STEPS *********************** */

    /* ******************************* */
    // for first filepath packet
    n = recvfrom(socket_fd, (char *)buffer, MAX_BUFF_LINE, MSG_WAITALL, (struct sockaddr *)&client_address, &client_len);
    buffer[n] = '\0';

    // struct in_addr *client_address2 = client_address;

    dns_receiver__on_transfer_init(&client_address.sin_addr);

    char toSend[400];
    memset(toSend, 0, 400);

    int first_size = 0;
    dns_receiver__on_query_parsed(DST_dirpath, buffer);
    char *send_file = extractFirstPacket(buffer, toSend, &first_size);

    strcat(DST_dirpath, send_file);
    dns_receiver__on_transfer_completed(DST_dirpath, strlen(send_file));
    dns_receiver__on_chunk_received(&client_address.sin_addr, DST_dirpath, 0x0100, strlen(send_file));

    // sending response
    char file_response[400] = "80000001000000010000";
    strcat(file_response, toSend);
    strcat(file_response, "000001000100000e10000401020302");
    sendto(socket_fd, (const char *)file_response, strlen(file_response), MSG_CONFIRM, (const struct sockaddr *)&client_address, client_len);

    /* ******************************* */
    file = fopen(DST_dirpath, "wt");
    free(send_file);

    // a main loop for reciving all data
    int size_counter = 0;
    int size_temp = 0;
    while (1)
    {
        n = recvfrom(socket_fd, (char *)buffer, MAX_BUFF_LINE, MSG_WAITALL, (struct sockaddr *)&client_address, &client_len);
        buffer[n] = '\0';

        dns_receiver__on_query_parsed(DST_dirpath, buffer);

        /* ********************************** */
        char buff_temp[13];
        int n;
        for (n = 36; n < 48; n++)
        {
            buff_temp[n - 36] = buffer[n];
        }
        buff_temp[n] = '\0';
        if (strcmp(buff_temp, "0x08IVHEICQ9") == 0)
            break;
        /* ********************************** */

        memset(toSend, 0, 400);
        size_temp = size_counter;
        extractPacket(buffer, base_host, toSend, &size_counter);

        dns_receiver__on_chunk_received(&client_address.sin_addr, DST_dirpath, 0x0100, size_counter - size_temp);

        char response[400] = "80000001000000010000";
        strcat(response, toSend);
        strcat(response, "000001000100000e10000401020302");
        sendto(socket_fd, (const char *)response, strlen(response), MSG_CONFIRM, (const struct sockaddr *)&client_address, client_len);
    }

    dns_receiver__on_transfer_completed(DST_dirpath, size_counter);

    fclose(file);
    return 0;
}
