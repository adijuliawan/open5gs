#include "kmu_kdf.h"
#include "kmu_sha2_hmac.h"


#define FC_FOR_CK_PRIME_IK_PRIME_DERIVATION     0x20
#define MAX_NUM_OF_KDF_PARAM                    16

typedef struct kdf_param_s {
    const uint8_t *buf;
    uint16_t len;
} kdf_param_t[MAX_NUM_OF_KDF_PARAM];

/* KDF function : TS.33220 cluase B.2.0 */
static void kmu_kdf_common(const uint8_t *key, uint32_t key_size,
        uint8_t fc, kdf_param_t param, uint8_t *output)
{
    int i = 0, pos;
    uint8_t *s = NULL;

    // ogs_assert(key);
    // ogs_assert(key_size);
    // ogs_assert(fc);
    // ogs_assert(param[0].buf);
    // ogs_assert(param[0].len);
    // ogs_assert(output);

    pos = 1; /* FC Value */

    /* Calculate buffer length */
    for (i = 0; i < MAX_NUM_OF_KDF_PARAM && param[i].buf && param[i].len; i++) {
        pos += (param[i].len + 2);
    }

    s = calloc(1, pos);
    
    /* Copy buffer from param */
    pos = 0;
    s[pos++] = fc;
    for (i = 0; i < MAX_NUM_OF_KDF_PARAM && param[i].buf && param[i].len; i++) {
        //uint16_t len;
        uint8_t len_buf[2];

        memcpy(&s[pos], param[i].buf, param[i].len);
        pos += param[i].len;
        //len = htons(param[i].len);
        len_buf[0] = (param[i].len >> 8) & 0xFF;
        len_buf[1] = param[i].len & 0xFF;
        
        memcpy(&s[pos], len_buf, sizeof(len_buf));
        pos += 2;
    }

    kmu_hmac_sha256(key, key_size, s, pos, output, KMU_SHA256_DIGEST_SIZE);

    free(s);
}

/* TS33.501 Annex A.3 : CK' and IK' derivation function */
void kmu_kdf_ck_prime_ik_prime(
    uint8_t *ck, uint8_t *ik,
    char *serving_network_name, uint8_t *sqn, uint8_t *ak,
    uint8_t *ck_prime, uint8_t *ik_prime)
{
    kdf_param_t param;
    int i;
    uint8_t key[16];
    uint8_t output[16];
    uint8_t sqn_xor_ak[6];

    // TODO: make function to check value inside variable

    // ogs_assert(ck);
    // ogs_assert(ik);
    // ogs_assert(serving_network_name);
    // ogs_assert(sqn);
    // ogs_assert(ak);
    // ogs_assert(ck_prime);
    // ogs_assert(ik_prime);

    memcpy(key, ck, 8);
    memcpy(key + 8, ik, 8);

    for (i = 0; i < 6; i++)
        sqn_xor_ak[i] = sqn[i] ^ ak[i];

    memset(param, 0, sizeof(param));
    param[0].buf = (uint8_t *)serving_network_name;
    param[0].len = strlen(serving_network_name);
    param[1].buf = sqn_xor_ak;
    param[1].len = 6;

    kmu_kdf_common(key, 16,
        FC_FOR_CK_PRIME_IK_PRIME_DERIVATION, param, output);

    memcpy(ck_prime, output, 8);
    memcpy(ik_prime, output+8, 8);
}