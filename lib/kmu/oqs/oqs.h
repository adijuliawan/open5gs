/**
 * \file oqs.h
 * \brief Overall header file for the liboqs public API.
 *
 * C programs using liboqs can include just this one file, and it will include all
 * other necessary headers from liboqs.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_H
#define OQS_H

#include <kmu/oqs/oqsconfig.h>

#include <kmu/oqs/common.h>
#include <kmu/oqs/rand.h>
#include <kmu/oqs/kem.h>
#include <kmu/oqs/sig.h>
#include <kmu/oqs/sig_stfl.h>
#include <kmu/oqs/aes_ops.h>
#include <kmu/oqs/sha2_ops.h>
#include <kmu/oqs/sha3_ops.h>
#include <kmu/oqs/sha3x4_ops.h>

#endif // OQS_H
