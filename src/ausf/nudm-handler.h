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

#ifndef AUSF_NUDM_HANDLER_H
#define AUSF_NUDM_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

bool ausf_nudm_ueau_handle_get(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool ausf_nudm_ueau_handle_result_confirmation_inform(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
bool ausf_nudm_ueau_handle_auth_removal_ind(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);
void write_be16(uint8_t *dst, uint16_t val);
int encode_at_rand(uint8_t *buf, const uint8_t *rand);
int encode_at_autn(uint8_t *buf, const uint8_t *autn);
int encode_at_kdf(uint8_t *buf);
void int_to_bytes_be(uint16_t value, uint8_t *out);
void pad_zeros(const uint8_t *input, size_t input_len, uint8_t *output, size_t padded_len);
int encode_at_kdf_input(uint8_t *buf, const uint8_t *data, size_t len);
int encode_at_res(uint8_t *buf, const uint8_t *data, size_t len);
int encode_at_mac(uint8_t *buf);
void calculate_at_mac(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *mac_out);
char *base64_encode(const uint8_t *data, size_t len);


#ifdef __cplusplus
}
#endif

#endif /* AUSF_NUDM_HANDLER_H */
