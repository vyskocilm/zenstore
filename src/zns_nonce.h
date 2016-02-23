/*  =========================================================================
    zns_nonce - Class wrapping array buffers

    Copyright (c) the Contributors as noted in the AUTHORS file.       
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

#ifndef ZNS_NONCE_H_INCLUDED
#define ZNS_NONCE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _zns_nonce_t zns_nonce_t;

//  @interface
//  Create a new zns_nonce
ZNS_EXPORT zns_nonce_t *
    zns_nonce_new (void);

//  Check if nonce is initialized or zero
ZNS_EXPORT bool
    zns_nonce_initialized (zns_nonce_t* self);

//  Generate random nonce using libsodium routines
ZNS_EXPORT void
    zns_nonce_rand (zns_nonce_t *self);

//  Convert the nonce to hexadecimal representation compatible with C strings
//  including ending \0. Caller is responsible for free'ing the memory.
ZNS_EXPORT char*
    zns_nonce_str (zns_nonce_t *self);

//  Setup the nonce from hexadecimal representation (see zns_nonce_str).
ZNS_EXPORT int
    zns_nonce_from_str (zns_nonce_t *self, const char* nonce_str);

//  Return raw representation of nonce.
//  WARNING: this gives you an access to internal buffer, DO NOT MESS WITH IT!
ZNS_EXPORT const byte*
    zns_nonce_raw (zns_nonce_t *self);

//  Destroy the zns_nonce
ZNS_EXPORT void
    zns_nonce_destroy (zns_nonce_t **self_p);

//  Self test of this class
ZNS_EXPORT void
    zns_nonce_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
