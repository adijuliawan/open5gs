#ifndef KMU_BASE64_H
#define KMU_BASE64_H


#include <stddef.h>
#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" {
#endif



int kmu_base64_decode_len(const char *bufcoded);
int kmu_base64_decode(char *bufplain, const char *bufcoded);
int kmu_base64_decode_binary(
        unsigned char *bufplain, const char *bufcoded);

int kmu_base64_encode_len(int len);
int kmu_base64_encode(
        char *encoded, const char *string, int len);
int kmu_base64_encode_binary(
        char *encoded, const unsigned char *string, int len);


#ifdef __cplusplus
}
#endif

#endif /* KMU_BASE64_H */