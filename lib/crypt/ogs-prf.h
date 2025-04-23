
#if !defined(OGS_CRYPT_INSIDE) && !defined(OGS_CRYPT_COMPILATION)
#error "This header cannot be included directly."
#endif

#ifndef OGS_PRF_H
#define OGS_PRF_H

#ifdef __cplusplus
extern "C" {
#endif


/* RFC 5448 3.4.1 PRF' */
void ogs_prf_prime(uint8_t *key, size_t key_len, uint8_t *input, size_t input_len, uint8_t *output, size_t output_len);


#ifdef __cplusplus
}
#endif

#endif /* OGS_PRF_H */
