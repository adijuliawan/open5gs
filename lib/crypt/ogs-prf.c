#include "ogs-crypt.h"

/* RFC 5448 3.4.1 PRF' 

The PRF' construction is the same one IKEv2 uses (see Section 2.13 of
    [RFC4306]).  The function takes two arguments.  K is a 256-bit value
    and S is an octet string of arbitrary length.  PRF' is defined as
    follows:

PRF'(K,S) = T1 | T2 | T3 | T4 | ...

    where:
    T1 = HMAC-SHA-256 (K, S | 0x01)
    T2 = HMAC-SHA-256 (K, T1 | S | 0x02)
    T3 = HMAC-SHA-256 (K, T2 | S | 0x03)
    T4 = HMAC-SHA-256 (K, T3 | S | 0x04)
    ...

PRF' produces as many bits of output as is needed.  HMAC-SHA-256 is
the application of HMAC [RFC2104] to SHA-256.

For EAP-AKA', output is 1664 bits = 208 bytes 

For EAP-AKA'FS, there is 2 
    MK is 384 bits = 48 bytes
    MK_ECDHE is 1280 = 160 bytes 

For EAP-AKA'-HPQC
    MK is 384 bits = 48 bytes 
    MK_HYBRID is 1280 = 160 bytes

*/

void ogs_prf_prime(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output, size_t output_len)
{
    ogs_assert(key);
    ogs_assert(input);

    int i = 0;
    int round = output_len / 32 + 1;  
    uint8_t *s = NULL;

    uint8_t **T = calloc(round, sizeof(uint8_t *));
   
    for (i = 0; i < round ; i++){
        int s_len = (i == 0 ? 0 : 32) + input_len + 1;

        s = ogs_calloc(1, s_len);
        
        if(!s){
            ogs_free(s);
        }

        int pos = 0;
        if (i == 0) {
            memcpy(s + pos, input, input_len);
            pos += input_len;
        } else {
            memcpy(s + pos, T[i - 1], 32);
            pos += 32;
            memcpy(s + pos, input, input_len);
            pos += input_len;
        }

        s[pos++] = (uint8_t)(i + 1);
        
        T[i] = malloc(OGS_SHA256_DIGEST_SIZE);
        
        ogs_hmac_sha256(key, key_len , s, s_len,  T[i], 32);

        ogs_free(s);
        
    } 

    size_t total_len = round * 32;
    uint8_t result[total_len];

    for (i = 0; i < round; i++) {
        memcpy(result + i * 32, T[i], 32);
        free(T[i]);
    }

    memcpy(output, result, output_len);
}
