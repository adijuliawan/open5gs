#ifndef KMU_COMMON_H
#define KMU_COMMON_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif


char *kmu_id_get_value(const char *str);


#ifdef __cplusplus
}
#endif

#endif /* KMU_COMMON_H */