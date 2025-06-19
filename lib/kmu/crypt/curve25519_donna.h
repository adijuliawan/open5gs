#ifndef CURVE25519_DONNA_H
#define CURVE25519_DONNA_H



#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h> 

int kmu_curve25519_donna(
        uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);


#ifdef __cplusplus
}
#endif

#endif /* CURVE25519_DONNA_H */