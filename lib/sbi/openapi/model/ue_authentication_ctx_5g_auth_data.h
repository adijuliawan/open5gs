/*
 * ue_authentication_ctx_5g_auth_data.h
 *
 * 
 */

#ifndef _OpenAPI_ue_authentication_ctx_5g_auth_data_H_
#define _OpenAPI_ue_authentication_ctx_5g_auth_data_H_

#include <string.h>
#include "../external/cJSON.h"
#include "../include/list.h"
#include "../include/keyValuePair.h"
#include "../include/binary.h"
#include "av5g_aka.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OpenAPI_ue_authentication_ctx_5g_auth_data_s OpenAPI_ue_authentication_ctx_5g_auth_data_t;
typedef struct OpenAPI_eap_payload_s {
    bool is_eap_payload_null;
    char *eap_payload;
} OpenAPI_eap_payload_t;
typedef struct OpenAPI_av_5g_aka_s {
    char *rand;
    char *hxres_star;
    char *autn;
} OpenAPI_av_5g_aka_t;

typedef struct OpenAPI_ue_authentication_ctx_5g_auth_data_s {
    union {
        OpenAPI_av_5g_aka_t av_5g_aka;
        OpenAPI_eap_payload_t eap_payload;
    };
    bool is_eap_payload;
} OpenAPI_ue_authentication_ctx_5g_auth_data_t;

OpenAPI_ue_authentication_ctx_5g_auth_data_t *OpenAPI_ue_authentication_ctx_5g_auth_data_create_av_5g_aka(
    char *rand,
    char *hxres_star,
    char *autn
);
OpenAPI_ue_authentication_ctx_5g_auth_data_t *OpenAPI_ue_authentication_ctx_5g_auth_data_create_eap_payload(
    char *eap_payload
);
void OpenAPI_ue_authentication_ctx_5g_auth_data_free(OpenAPI_ue_authentication_ctx_5g_auth_data_t *ue_authentication_ctx_5g_auth_data);
OpenAPI_ue_authentication_ctx_5g_auth_data_t *OpenAPI_ue_authentication_ctx_5g_auth_data_parseFromJSON(cJSON *ue_authentication_ctx_5g_auth_dataJSON);
cJSON *OpenAPI_ue_authentication_ctx_5g_auth_data_convertToJSON(OpenAPI_ue_authentication_ctx_5g_auth_data_t *ue_authentication_ctx_5g_auth_data);
OpenAPI_ue_authentication_ctx_5g_auth_data_t *OpenAPI_ue_authentication_ctx_5g_auth_data_copy(OpenAPI_ue_authentication_ctx_5g_auth_data_t *dst, OpenAPI_ue_authentication_ctx_5g_auth_data_t *src);

#ifdef __cplusplus
}
#endif

#endif /* _OpenAPI_ue_authentication_ctx_5g_auth_data_H_ */

