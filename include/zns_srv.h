/*  =========================================================================
    zns_srv - Actor providing ZeroMQ socket based interface to zns_store

    Copyright (c) the Contributors as noted in the AUTHORS file.       
    This file is part of zenstore - ZeroMQ based encrypted store.      
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

#ifndef ZNS_SRV_H_INCLUDED
#define ZNS_SRV_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif


//  @interface
//  Create new zns_srv actor instance.
//  @TODO: Describe the purpose of this actor!
//
//      zactor_t *zns_srv = zactor_new (zns_srv, NULL);
//
//  Destroy zns_srv instance.
//
//      zactor_destroy (&zns_srv);
//
//  Enable verbose logging of commands and activity:
//
//      zstr_send (zns_srv, "VERBOSE");
//
//  Start zns_srv actor.
//
//      zstr_sendx (zns_srv, "START", NULL);
//
//  Stop zns_srv actor.
//
//      zstr_sendx (zns_srv, "STOP", NULL);
//
//  This is the zns_srv constructor as a zactor_fn;
ZNS_EXPORT void
    zns_srv_actor (zsock_t *pipe, void *args);

//  Self test of this actor
ZNS_EXPORT void
    zns_srv_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

#endif
