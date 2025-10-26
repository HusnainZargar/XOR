/*
 * Project: GhostXor
 * Coded by: Muhammad Husnain Zargar
 * Email: hackwithhusnain@gmail.com
 * Purpose: A custom XOR-based encryption tool that encrypts and decrypts data 
   using XOR operations combined with bit-flipping for extra obfuscation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     
#include <sys/stat.h>   
#include <errno.h>

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define MAGENTA "\033[35m"
#define RESET   "\033[0m"

void banner()
{
    printf(RED
R"(
  ________.__                    __ ____  ___            
 /  _____/|  |__   ____  _______/  |\   \/  /___________ 
/   \  ___|  |  \ /  _ \/  ___/\   __\     //  _ \_  __ \
\    \_\  \   Y  (  <_> )___ \  |  | /     (  <_> )  | \/
 \______  /___|  /\____/____  > |__|/___/\  \____/|__|   
        \/     \/           \/            \_/              

)");
    printf(MAGENTA"                XOR Encryptor V2.0.0\n");
    printf("           Author: Muhammad Husnain Zargar\n");
}
void help()
{
    printf(RESET "\nA custom XOR-based encryption tool that encrypts and \ndecrypts data using XOR operations with bit-flipping \nfor added obfuscation.\n\n");
    printf(YELLOW "[*]" RESET " Usage: ./Xor-Encryptor -e -k <KEY> -f <FILE>\n");
    printf(YELLOW "\n[*]" RESET " Options:\n");
    printf("\n  -e         Encrypt the file\n");
    printf("  -d         Decrypt the file\n");
    printf("  -k <KEY>   Secret key to use\n");
    printf("  -f <FILE>  File name or Path (For Encryption/Decryption)\n");
    printf("  -h         Show this help\n\n");
    printf(YELLOW "[*]" RESET " Examples:\n");
    printf("\n  ./Xor-Encryptor -e -k secretKey -f data.txt\n");
    printf("  ./Xor-Encryptor -d -k secretKey -f data.encrypted.enc\n\n");
}

int read_file_to_buffer(const char *path, unsigned char **out_buf, size_t *out_len)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    size_t fsize = (size_t)st.st_size;
    if (fsize == 0) {
        *out_buf = NULL;
        *out_len = 0;
        return 0;
    }

    unsigned char *buf = malloc(fsize);
    if (!buf) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) {
        free(buf);
        return -1;
    }

    size_t read = fread(buf, 1, fsize, f);
    fclose(f);

    if (read != fsize) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = fsize;
    return 0;
}

int write_buffer_to_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    size_t written = fwrite(buf, 1, len, f);
    fclose(f);

    if (written != len) return -1;
    return 0;
}

void xor_double_transform_chunk(const unsigned char *in, unsigned char *out, size_t len,
                                const unsigned char *key, size_t keylen, size_t *key_index, int encrypt)
{
    size_t j = *key_index;
    for (size_t i = 0; i < len; ++i) {
        unsigned char k = key[j % keylen];
        if (encrypt) {
            unsigned char t_not = ~in[i];
            out[i] = t_not ^ k;
        } else {
            unsigned char t = in[i] ^ k;
            out[i] = ~t;
        }
        j++;
    }
    *key_index = j % keylen;
}

char* bytesToHex(const unsigned char *bytes, int len) {
    char *hexOut = malloc(len * 2 + 1);
    if (!hexOut) return NULL;
    for (int i = 0; i < len; i++)
        sprintf(hexOut + i * 2, "%02X", bytes[i]);
    hexOut[len * 2] = '\0';
    return hexOut;
}

int hexToBytes(const char *hex, unsigned char *bytesOut) {
    int len = strlen(hex);
    if (len % 2 != 0) return -1;

    for (int i = 0; i < len / 2; i++)
        sscanf(hex + 2 * i, "%2hhx", &bytesOut[i]);
    return len / 2;
}

void build_output_filename(const char *input_file, char *output_file, const char *suffix) {
    const char *dot = strchr(input_file, '.');
    size_t len;

    if (dot) {
        len = (size_t)(dot - input_file);
    } else {
        len = strlen(input_file);
    }

    strncpy(output_file, input_file, len);
    output_file[len] = '\0';
    strcat(output_file, suffix);
}

int process_file(const char *path, const char *key_str, int do_encrypt)
{
    unsigned char *in_buf = NULL;
    size_t in_len = 0;

    if (read_file_to_buffer(path, &in_buf, &in_len) != 0) {
        fprintf(stderr, RED "\n[-]" RESET " Error: file '%s' not found or unreadable \n(%s)\n", path, strerror(errno));
        return 1;
    }

    if (in_len == 0) {
        fprintf(stdout, YELLOW "\n[*]" RESET " Warning: file '%s' is empty. Nothing to do.\n", path);
        free(in_buf);
        return 0;
    }

    size_t keylen = strlen(key_str);
    if (keylen == 0) {
        fprintf(stderr, RED "\n[-]" RESET " Error: key length is zero\n");
        free(in_buf);
        return 1;
    }

    const unsigned char *key = (const unsigned char *)key_str;
    char output_file[512];

    if (do_encrypt) {
        
        build_output_filename(path, output_file, ".encrypted.enc");

        unsigned char *out_buf = malloc(in_len);
        if (!out_buf) {
            fprintf(stderr, RED "\n[-]" RESET " Memory allocation failed\n");
            free(in_buf);
            return 1;
        }

        size_t key_index = 0;
        xor_double_transform_chunk(in_buf, out_buf, in_len, key, keylen, &key_index, 1);

        char *hex = bytesToHex(out_buf, (int)in_len);
        free(out_buf);
        if (!hex) {
            fprintf(stderr, RED "\n[-]" RESET " Hex conversion failed\n");
            free(in_buf);
            return 1;
        }

        if (write_buffer_to_file(output_file, (unsigned char *)hex, strlen(hex)) != 0) {
            fprintf(stderr, RED "\n[-]" RESET " Failed to write %s (%s)\n", output_file, strerror(errno));
            free(in_buf);
            free(hex);
            return 1;
        }

        free(in_buf);
        free(hex);
        printf(GREEN "\n[+]" RESET " Encryption successful. File Created: %s\n", output_file);
        return 0;
    } else {
       
        build_output_filename(path, output_file, ".decrypted.dec");

        if (in_len % 2 != 0) {
            fprintf(stderr, RED "\n[-]" RESET " Invalid hex input length.\n");
            free(in_buf);
            return 1;
        }

        size_t bin_len = in_len / 2;
        unsigned char *bin_in = malloc(bin_len + 1);
        if (!bin_in) {
            fprintf(stderr, RED "\n[-]" RESET " Memory allocation failed\n");
            free(in_buf);
            return 1;
        }

        char *temp_str = malloc(in_len + 1);
        memcpy(temp_str, in_buf, in_len);
        temp_str[in_len] = '\0';

        int parsed = hexToBytes(temp_str, bin_in);
        free(temp_str);
        if (parsed < 0) {
            fprintf(stderr, RED "\n[-]" RESET " Hex parsing failed.\n");
            free(in_buf);
            free(bin_in);
            return 1;
        }

        unsigned char *out_buf = malloc(parsed);
        if (!out_buf) {
            fprintf(stderr, RED "\n[-]" RESET " Memory allocation failed\n");
            free(in_buf);
            free(bin_in);
            return 1;
        }

        size_t key_index = 0;
        xor_double_transform_chunk(bin_in, out_buf, (size_t)parsed, key, keylen, &key_index, 0);

        if (write_buffer_to_file(output_file, out_buf, (size_t)parsed) != 0) {
            fprintf(stderr, RED "\n[-]" RESET " Failed to write %s (%s)\n", output_file, strerror(errno));
            free(in_buf);
            free(bin_in);
            free(out_buf);
            return 1;
        }

        free(in_buf);
        free(bin_in);
        free(out_buf);
        printf(GREEN "\n[+]" RESET " Decryption successful. File Created: %s\n", output_file);
        return 0;
    }
}

int main(int argc, char * argv[])
{
    banner();
    if(argc!=6)
    {
      help();
      return 1;
    }
    else{
    int opt;
    int do_encrypt = 0;
    int do_decrypt = 0;
    char *key = NULL;
    char *file = NULL;

    while ((opt = getopt(argc, argv, "edk:f:h")) != -1) {
        switch (opt) {
            case 'e': do_encrypt = 1; break;
            case 'd': do_decrypt = 1; break;
            case 'k': key = optarg; break;
            case 'f': file = optarg; break;
            case 'h':
            default: help(); return 0;
        }
    }

    process_file(file, key, do_encrypt);
  }
  return 0;
}
