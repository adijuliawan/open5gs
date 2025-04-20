/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "nausf-handler.h"
#include "nas-path.h"

static int amf_nausf_auth_handle_authenticate_5g_aka(
        amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    int r;
    OpenAPI_ue_authentication_ctx_t *UeAuthenticationCtx = NULL;
    OpenAPI_ue_authentication_ctx_5g_auth_data_t *AuthData = NULL;
    OpenAPI_links_value_schema_t *LinksValueSchemeValue = NULL;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_lnode_t *node = NULL;

    bool rc;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(amf_ue);
    ogs_assert(message);

    if (!message->http.location) {
        ogs_error("[%s] No http.location", amf_ue->suci);
        return OGS_ERROR;
    }

    UeAuthenticationCtx = message->UeAuthenticationCtx;
    ogs_assert(UeAuthenticationCtx);
    ogs_assert(UeAuthenticationCtx->auth_type == OpenAPI_auth_type_5G_AKA);
    // if (!UeAuthenticationCtx) {
    //     ogs_error("[%s] No UeAuthenticationCtx", amf_ue->suci);
    //     return OGS_ERROR;
    // }

    // if (UeAuthenticationCtx->auth_type != OpenAPI_auth_type_5G_AKA) {
    //     ogs_error("[%s] Not supported Auth Method [%d]",
    //         amf_ue->suci, UeAuthenticationCtx->auth_type);
    //     return OGS_ERROR;
    // }

    AuthData = UeAuthenticationCtx->_5g_auth_data;
    if (!AuthData) {
        ogs_error("[%s] No Av5gAka", amf_ue->suci);
        return OGS_ERROR;
    }

    if (AuthData->is_eap_payload) {
        ogs_error("[%s] 5G-AKA AuthData with EAP payload", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AuthData->av_5g_aka.rand) {
        ogs_error("[%s] No Av5gAka.rand", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AuthData->av_5g_aka.hxres_star) {
        ogs_error("[%s] No Av5gAka.hxresStar", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AuthData->av_5g_aka.autn) {
        ogs_error("[%s] No Av5gAka.autn", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!UeAuthenticationCtx->_links) {
        ogs_error("[%s] No _links", amf_ue->suci);
        return OGS_ERROR;
    }

    OpenAPI_list_for_each(UeAuthenticationCtx->_links, node) {
        LinksValueScheme = node->data;
        if (LinksValueScheme) {
            if (strcmp(LinksValueScheme->key,
                        OGS_SBI_RESOURCE_NAME_5G_AKA) == 0) {
                LinksValueSchemeValue = LinksValueScheme->value;
                break;
            }
        }
    }

    if (!LinksValueSchemeValue) {
        ogs_error("[%s] No _links.5g-aka", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!LinksValueSchemeValue->href) {
        ogs_error("[%s] No _links.5g-aka.href", amf_ue->suci);
        return OGS_ERROR;
    }

    rc = ogs_sbi_getaddr_from_uri(
            &scheme, &fqdn, &fqdn_port, &addr, &addr6, message->http.location);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                amf_ue->suci, message->http.location);
        return OGS_ERROR;
    }

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("[%s] ogs_sbi_client_add()", amf_ue->suci);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            ogs_error("[%s] ogs_sbi_client_add() failed", amf_ue->suci);

            ogs_free(fqdn);
            ogs_freeaddrinfo(addr);
            ogs_freeaddrinfo(addr6);

            return OGS_ERROR;
        }
    }

    OGS_SBI_SETUP_CLIENT(&amf_ue->confirmation_for_5g_aka, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    STORE_5G_AKA_CONFIRMATION(amf_ue, LinksValueSchemeValue->href);

    ogs_ascii_to_hex(AuthData->av_5g_aka.rand, strlen(AuthData->av_5g_aka.rand),
        amf_ue->rand, sizeof(amf_ue->rand));
    ogs_ascii_to_hex(AuthData->av_5g_aka.hxres_star, strlen(AuthData->av_5g_aka.hxres_star),
        amf_ue->hxres_star, sizeof(amf_ue->hxres_star));
    ogs_ascii_to_hex(AuthData->av_5g_aka.autn, strlen(AuthData->av_5g_aka.autn),
        amf_ue->autn, sizeof(amf_ue->autn));

    /* Clear Security Context */
    CLEAR_SECURITY_CONTEXT(amf_ue);

    if (amf_ue->nas.amf.ksi < (OGS_NAS_KSI_NO_KEY_IS_AVAILABLE - 1))
        amf_ue->nas.amf.ksi++;
    else
        amf_ue->nas.amf.ksi = 0;

    amf_ue->nas.ue.ksi = amf_ue->nas.amf.ksi;

    r = nas_5gs_send_authentication_request(amf_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return OGS_OK;
}

static int amf_nausf_auth_handle_authenticate_eap_aka_prime(
    amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    int r;
    OpenAPI_ue_authentication_ctx_t *UeAuthenticationCtx = NULL;
    OpenAPI_ue_authentication_ctx_5g_auth_data_t *AuthData = NULL;
    OpenAPI_links_value_schema_t *LinksValueSchemeValue = NULL;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_lnode_t *node = NULL;

    bool rc;
    ogs_sbi_client_t *client = NULL;
    OpenAPI_uri_scheme_e scheme = OpenAPI_uri_scheme_NULL;
    char *fqdn = NULL;
    uint16_t fqdn_port = 0;
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(amf_ue);
    ogs_assert(message);

    if (!message->http.location) {
        ogs_error("[%s] No http.location", amf_ue->suci);
        return OGS_ERROR;
    }

    UeAuthenticationCtx = message->UeAuthenticationCtx;
    // if (!UeAuthenticationCtx) {
    //     ogs_error("[%s] No UeAuthenticationCtx", amf_ue->suci);
    //     return OGS_ERROR;
    // }

    // if (UeAuthenticationCtx->auth_type != OpenAPI_auth_type_EAP_AKA_PRIME) {
    //     ogs_error("[%s] Not supported Auth Method [%d]",
    //         amf_ue->suci, UeAuthenticationCtx->auth_type);
    //     return OGS_ERROR;
    // }
    ogs_assert(UeAuthenticationCtx);
    ogs_assert(UeAuthenticationCtx->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME);

    AuthData = UeAuthenticationCtx->_5g_auth_data;
    if (!AuthData) {
        ogs_error("[%s] No AuthData", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!AuthData->is_eap_payload) {
        ogs_error("[%s] EAP-AKA-PRIME AuthData without EAP payload", amf_ue->suci);
        return OGS_ERROR;
    }

    if (AuthData->eap_payload.is_eap_payload_null) {
        ogs_error("[%s] EAP-AKA-PRIME AuthData with NULL EAP payload", amf_ue->suci);
        return OGS_ERROR;
    }
    ogs_assert(AuthData->eap_payload.eap_payload);
    
    
    if (!UeAuthenticationCtx->_links) {
        ogs_error("[%s] No _links", amf_ue->suci);
        return OGS_ERROR;
    }
        

    OpenAPI_list_for_each(UeAuthenticationCtx->_links, node) {
        LinksValueScheme = node->data;
        if (LinksValueScheme) {
            if (strcmp(LinksValueScheme->key,
                        OGS_SBI_RESOURCE_NAME_EAP_SESSION) == 0) {
                LinksValueSchemeValue = LinksValueScheme->value;
                break;
            }
        }
    }

    if (!LinksValueSchemeValue) {
        ogs_error("[%s] No _links.eap-session", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!LinksValueSchemeValue->href) {
        ogs_error("[%s] No _links.eap-session.href", amf_ue->suci);
        return OGS_ERROR;
    }

    rc = ogs_sbi_getaddr_from_uri(
            &scheme, &fqdn, &fqdn_port, &addr, &addr6, message->http.location);
    if (rc == false || scheme == OpenAPI_uri_scheme_NULL) {
        ogs_error("[%s] Invalid URI [%s]",
                amf_ue->suci, message->http.location);
        return OGS_ERROR;
    }

    client = ogs_sbi_client_find(scheme, fqdn, fqdn_port, addr, addr6);
    if (!client) {
        ogs_debug("[%s] ogs_sbi_client_add()", amf_ue->suci);
        client = ogs_sbi_client_add(scheme, fqdn, fqdn_port, addr, addr6);
        if (!client) {
            ogs_error("[%s] ogs_sbi_client_add() failed", amf_ue->suci);

            ogs_free(fqdn);
            ogs_freeaddrinfo(addr);
            ogs_freeaddrinfo(addr6);

            return OGS_ERROR;
        }
    }

    OGS_SBI_SETUP_CLIENT(&amf_ue->confirmation_for_5g_aka, client);

    ogs_free(fqdn);
    ogs_freeaddrinfo(addr);
    ogs_freeaddrinfo(addr6);

    STORE_5G_AKA_CONFIRMATION(amf_ue, LinksValueSchemeValue->href);

    amf_ue->auth_type = OpenAPI_auth_type_EAP_AKA_PRIME;
    
    // AMF only forward eap payload from AUSF to UE
    size_t payload_len = strlen(AuthData->eap_payload.eap_payload);
    if (payload_len > sizeof(amf_ue->eap_payload)) {
        ogs_error("[%s] EAP payload too long", amf_ue->suci);
        return OGS_ERROR;
    }
    memcpy(amf_ue->eap_payload, AuthData->eap_payload.eap_payload,
            strlen(AuthData->eap_payload.eap_payload));

    /* Clear Security Context */
    CLEAR_SECURITY_CONTEXT(amf_ue);

    if (amf_ue->nas.amf.ksi < (OGS_NAS_KSI_NO_KEY_IS_AVAILABLE - 1))
        amf_ue->nas.amf.ksi++;
    else
        amf_ue->nas.amf.ksi = 0;

    amf_ue->nas.ue.ksi = amf_ue->nas.amf.ksi;

    r = nas_5gs_send_authentication_request(amf_ue);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return OGS_OK;
}

int amf_nausf_auth_handle_authenticate(
    amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    OpenAPI_ue_authentication_ctx_t *UeAuthenticationCtx = NULL;

    ogs_assert(amf_ue);
    ogs_assert(message);

    UeAuthenticationCtx = message->UeAuthenticationCtx;
    if (!UeAuthenticationCtx) {
        ogs_error("[%s] No UeAuthenticationCtx", amf_ue->suci);
        return OGS_ERROR;
    }

    if (UeAuthenticationCtx->auth_type == OpenAPI_auth_type_5G_AKA) {
        return amf_nausf_auth_handle_authenticate_5g_aka(amf_ue, message);
    } else if (UeAuthenticationCtx->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME) {
        return amf_nausf_auth_handle_authenticate_eap_aka_prime(amf_ue, message);
    } else {
        ogs_error("[%s] Auth Method Not Supported [%d]",
            amf_ue->suci, UeAuthenticationCtx->auth_type);
        return OGS_ERROR;
    }
}




int amf_nausf_auth_handle_authenticate_confirmation(
        amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];

    OpenAPI_confirmation_data_response_t *ConfirmationDataResponse;

    ogs_assert(amf_ue);
    ogs_assert(message);

    ConfirmationDataResponse = message->ConfirmationDataResponse;
    if (!ConfirmationDataResponse) {
        ogs_error("[%s] No ConfirmationDataResponse", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!ConfirmationDataResponse->supi) {
        ogs_error("[%s] No supi", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!ConfirmationDataResponse->kseaf) {
        ogs_error("[%s] No Kseaf", amf_ue->suci);
        return OGS_ERROR;
    }

    amf_ue->auth_result = ConfirmationDataResponse->auth_result;
    if (amf_ue->auth_result == OpenAPI_auth_result_AUTHENTICATION_SUCCESS) {

        amf_ue_set_supi(amf_ue, ConfirmationDataResponse->supi);
        ogs_ascii_to_hex(ConfirmationDataResponse->kseaf,
                strlen(ConfirmationDataResponse->kseaf), kseaf, sizeof(kseaf));

        ogs_kdf_kamf(amf_ue->supi, amf_ue->abba, amf_ue->abba_len,
                kseaf, amf_ue->kamf);

        return OGS_OK;

    } else {

        ogs_error("[%s] Authentication failed", amf_ue->suci);
        return OGS_ERROR;
    }
}

static int store_eap_payload(amf_ue_t *amf_ue, OpenAPI_eap_session_t *EapSession)
 {
     ogs_assert(amf_ue);
     ogs_assert(EapSession);
 
     if (EapSession->eap_payload == NULL) {
         ogs_error("[%s] No EAP payload", amf_ue->suci);
         return OGS_ERROR;
     }
     amf_ue->eap_payload_len = strlen(EapSession->eap_payload);
     if (amf_ue->eap_payload_len > sizeof(amf_ue->eap_payload)) {
         ogs_error("[%s] EAP payload too long (%u)", amf_ue->suci, amf_ue->eap_payload_len);
         amf_ue->eap_payload_len = 0;
         return OGS_ERROR;
     }
     memcpy(amf_ue->eap_payload, EapSession->eap_payload, amf_ue->eap_payload_len);
     return OGS_OK;
 }
 
 int amf_nausf_auth_handle_authenticate_eap_session(amf_ue_t *amf_ue, ogs_sbi_message_t *message)
 {
     OpenAPI_eap_session_t *EapSession = NULL;
     uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];
     int r = OGS_ERROR;
 
     ogs_assert(amf_ue);
     ogs_assert(message);
     memset(amf_ue->eap_payload, 0, sizeof(amf_ue->eap_payload));
     amf_ue->eap_payload_len = 0;
 
     EapSession = message->EapSession;
     if (!EapSession) {
         ogs_error("[%s] No EapSession", amf_ue->suci);
         return OGS_ERROR;
     }
 
     ogs_debug("[%s] Auth Result: %s", amf_ue->suci,
             OpenAPI_auth_result_ToString(EapSession->auth_result));
     amf_ue->auth_result = EapSession->auth_result;
 
     switch (amf_ue->auth_result) {
         case OpenAPI_auth_result_AUTHENTICATION_FAILURE:
         {
             ogs_error("[%s] Authentication failed", amf_ue->suci);
             break;
         }
         case OpenAPI_auth_result_AUTHENTICATION_SUCCESS:
         {
             if (!EapSession->supi) {
                 ogs_error("[%s] No supi", amf_ue->suci);
                 break;
             }
 
             if (!EapSession->k_seaf) {
                 ogs_error("[%s] No Kseaf", amf_ue->suci);
                 break;
             }
 
             amf_ue_set_supi(amf_ue, EapSession->supi);
             ogs_ascii_to_hex(EapSession->k_seaf,
                     strlen(EapSession->k_seaf), kseaf, sizeof(kseaf));
 
             ogs_kdf_kamf(amf_ue->supi, amf_ue->abba, amf_ue->abba_len,
                     kseaf, amf_ue->kamf);
             if (store_eap_payload(amf_ue, EapSession) != OGS_OK) {
                 ogs_error("[%s] Failed to store EAP payload in AMF UE", amf_ue->suci);
                 break;
             }
             OpenAPI_eap_session_free(EapSession);
             return OGS_OK;
         }
         case OpenAPI_auth_result_AUTHENTICATION_ONGOING:
         {
             /* send authentication result to UE */
             if (store_eap_payload(amf_ue, EapSession) != OGS_OK) {
                 ogs_error("[%s] Failed to store EAP payload in AMF UE", amf_ue->suci);
                 break;
             }
             r = nas_5gs_send_authentication_request(amf_ue);
             OpenAPI_eap_session_free(EapSession);
             return r;
         }
         default:
         {
             ogs_error("[%s] Unknown auth result", amf_ue->suci);
             ogs_assert_if_reached();
             break;
         }
     }
     amf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
     OpenAPI_eap_session_free(EapSession);
     return OGS_ERROR;
 }
