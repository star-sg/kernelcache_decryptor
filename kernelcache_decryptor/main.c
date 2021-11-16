//
//  main.c
//  kernelcache_decryptor
//
//  Created by Peter Nguyen on 14/11/21.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lzfse.h>
#include <limits.h>
#include <sys/stat.h>
#include "img4.h"

int file_get_content(const char *fn, unsigned char **file_data, uint32_t *data_length)
{
    FILE *fp;
    uint32_t file_size;
    
    fp = fopen(fn, "rb");
    if(!fp){
        fprintf(stderr, "Unable to open file %s\n", fn);
        return 1;
    }
    
    fseek(fp, 0, SEEK_END);
    file_size = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    *file_data = (unsigned char *)malloc(file_size);
    fread(*file_data, file_size, 1, fp);
    *data_length = file_size;
    fclose(fp);
    return 0;
}

int img4_extract(const char *fn, char *payload_type, unsigned char **payload_data, uint32_t *payload_data_length)
{
    /*
     Borrow from qemu-T8030 project and port it to work with mac mini M1
     */
    
    unsigned char *file_data;
    uint32_t file_size;
    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    asn1_node img4_definitions = NULL;
    asn1_node img4;
    int ret;
    char magic[4];
    char description[128];
    int len;
    
    if(file_get_content(fn, &file_data, &file_size)){
        return 1;
    }
    
    if (asn1_array2tree(img4_definitions_array, &img4_definitions, errorDescription)) {
        fprintf(stderr, "Could not initialize the ASN.1 parser: %s.", errorDescription);
        free(file_data);
        return 1;
    }
    
    if ((ret = asn1_create_element(img4_definitions, "Img4.Img4Payload", &img4) != ASN1_SUCCESS)) {
        fprintf(stderr, "Could not create an Img4Payload element: %d", ret);
        free(file_data);
        return 1;
    }
    
    if ((ret = asn1_der_decoding(&img4, (const uint8_t*)file_data, (uint32_t)file_size, errorDescription)) != ASN1_SUCCESS) {
        fprintf(stderr, "Could not parse asn1 img4: %d", ret);
        free(file_data);
        return 1;
    }
    
    len = 4;
    if ((ret = asn1_read_value(img4, "magic", magic, &len)) != ASN1_SUCCESS) {
        fprintf(stderr, "Failed to read the im4p magic in file '%s': %d.", fn, ret);
        free(file_data);
        return ret;
    }
    
    if (strncmp(magic, "IM4P", 4) != 0) {
        fprintf(stderr, "Couldn't parse ASN.1 data in file '%s' because it does not start with the IM4P header.", fn);
        free(file_data);
        return ret;
    }
    
    len = 4;
    if ((ret = asn1_read_value(img4, "type", payload_type, &len)) != ASN1_SUCCESS) {
        fprintf(stderr, "Failed to read the im4p type in file '%s': %d.", fn, ret);
        return ret;
    }
    
    len = 128;
    if ((ret = asn1_read_value(img4, "description", description, &len)) != ASN1_SUCCESS) {
        fprintf(stderr, "Failed to read the im4p description in file '%s': %d.", fn, ret);
        free(file_data);
        return ret;
    }
    
    *payload_data = NULL;
    *payload_data_length = 0;
    
    // extract payload_data_length first
    if ((ret = asn1_read_value(img4, "data", *payload_data, (int *)payload_data_length) != ASN1_MEM_ERROR)) {
        fprintf(stderr, "Failed to read the im4p payload in file '%s': %d.", fn, ret);
        free(file_data);
        return ret;
    }
    
    // extract compressed payload data from IMG4 format
    *payload_data = (unsigned char *)malloc(*payload_data_length);
    if ((ret = asn1_read_value(img4, "data", *payload_data, (int *)payload_data_length) != ASN1_SUCCESS)) {
        fprintf(stderr, "Failed to read the im4p payload in file '%s': %d.", fn, ret);
        free(file_data);
        return ret;
    }
    
    /*
     Determine whether the payload is LZFSE-compressed: LZFSE-compressed files contains various buffer blocks,
     and each buffer block starts with bvx? magic, where ? is -, 1, 2 or n.
     See https://github.com/lzfse/lzfse/blob/e634ca58b4821d9f3d560cdc6df5dec02ffc93fd/src/lzfse_internal.h
     for the details
     */
    if ((*payload_data)[0] == 'b' && (*payload_data)[1] == 'v' && (*payload_data)[2] == 'x') {
        size_t decode_buffer_size = *payload_data_length * 8;
        uint8_t *decode_buffer = (uint8_t *)malloc(decode_buffer_size);
        
        // decompress the payload
        int decoded_length = lzfse_decode_buffer(decode_buffer, decode_buffer_size, (const uint8_t *)*payload_data, (size_t)*payload_data_length, NULL);
        if (decoded_length == 0 || decoded_length == decode_buffer_size) {
            fprintf(stderr, "Could not decompress LZFSE-compressed data in file '%s' because the decode buffer was too small.", fn);
            free(file_data);
            free(*payload_data);
            free(decode_buffer);
            *payload_data = NULL;
            return 1;
        }
        
        free(*payload_data);
        *payload_data = decode_buffer;
        *payload_data_length = (uint32_t)decode_buffer_size;
    }
    
    free(file_data);
    return 0;
}

int main(int argc, const char * argv[]) {
    char kn_cache_out[PATH_MAX];
    struct stat kn_cache_stat;
    unsigned char *kernel_cache = NULL;
    uint32_t kernel_cache_size = 0;
    char payload_type[4];
    FILE *fp;
    
    if(argc < 2){
        printf("Usage %s: <kernelcache>\n", argv[0]);
        return 1;
    }
    
    if(stat(argv[1], &kn_cache_stat)){
        printf("File %s is not exists.\n",argv[1]);
        return 1;
    }
    
    bzero(kn_cache_out, PATH_MAX);
    snprintf(kn_cache_out, PATH_MAX, "%s.decrypt", argv[1]);
    
    if(img4_extract(argv[1], payload_type, &kernel_cache, &kernel_cache_size)){
        return 1;
    }
    
    printf("Extract kernelcache is done, writting kernelcache into file %s\n", kn_cache_out);
    fp = fopen(kn_cache_out, "wb");
    if(!fp){
        fprintf(stderr, "Unable to open file %s for writting.\n", kn_cache_out);
        return 1;
    }
    
    fwrite(kernel_cache, kernel_cache_size, 1, fp);
    fclose(fp);
    free(kernel_cache);
    puts("Done");
    
    return 0;
}
