/*  =========================================================================
    zns_store - The API for zns storage

    Copyright (c) the Contributors as noted in the AUTHORS file.       
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

#ifndef ZNS_STORE_H_INCLUDED
#define ZNS_STORE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new zns_store
ZNS_EXPORT zns_store_t *
    zns_store_new (void);

//  Destroy the zns_store
ZNS_EXPORT void
    zns_store_destroy (zns_store_t **self_p);

//  Self test of this class
ZNS_EXPORT void
    zns_store_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
