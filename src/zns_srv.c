/*  =========================================================================
    zns_srv - Actor providing ZeroMQ socket based interface to zns_store

    Copyright (c) the Contributors as noted in the AUTHORS file.       
    This file is part of zenstore - ZeroMQ based encrypted store.      
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

/*
@header
    zns_srv - Actor providing ZeroMQ socket based interface to zns_store
@discuss
@end
*/

#include "zns_classes.h"

//  Structure of our actor

struct _zns_srv_t {
    zsock_t *pipe;              //  Actor command pipe
    zpoller_t *poller;          //  Socket poller
    bool terminated;            //  Did caller ask us to quit?
    bool verbose;               //  Verbose logging enabled?
    //  Declare properties
    zsock_t *rw_socket;         //  Read write socket
    zns_store_t *store;         //  encrypted store
    byte password[crypto_secretbox_KEYBYTES];   //password
};


//  --------------------------------------------------------------------------
//  Create a new zns_srv instance

static zns_srv_t *
zns_srv_new (zsock_t *pipe, void *args)
{
    zns_srv_t *self = (zns_srv_t *) zmalloc (sizeof (zns_srv_t));
    assert (self);

    self->pipe = pipe;
    self->terminated = false;
    self->poller = zpoller_new (self->pipe, NULL);

    // Initialize properties
    self->rw_socket = NULL;
    self->store = zns_store_new ();
    sodium_memzero (self->password, crypto_secretbox_KEYBYTES);

    return self;
}


//  --------------------------------------------------------------------------
//  Destroy the zns_srv instance

static void
zns_srv_destroy (zns_srv_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        zns_srv_t *self = *self_p;

        // Free actor properties
        zsock_destroy (&self->rw_socket);
        zns_store_destroy (&self->store);
        sodium_memzero (self->password, crypto_secretbox_KEYBYTES);

        //  Free object itself
        zpoller_destroy (&self->poller);
        free (self);
        *self_p = NULL;
    }
}

void
zns_srv_set_password (zns_srv_t *self, const char *password)
{
    assert (self);
    size_t n = strlen (password) < crypto_secretbox_KEYBYTES ? strlen (password) : crypto_secretbox_KEYBYTES;
    memcpy (self->password, password, n);
}

//  Start this actor. Return a value greater or equal to zero if initialization
//  was successful. Otherwise -1.

static int
zns_srv_start (zns_srv_t *self)
{
    assert (self);
    int r = zns_store_load (self->store, self->password);
    if (r == -1)
        zsys_error ("Failed to open crypto store");

    return r;
}


//  Stop this actor. Return a value greater or equal to zero if stopping 
//  was successful. Otherwise -1.

static int
zns_srv_stop (zns_srv_t *self)
{
    assert (self);

    int r = zns_store_save (self->store, self->password);
    if (r == -1)
        zsys_error ("Failed to open crypto store");

    return r;
}


//  Here we handle incoming message from the node

static void
zns_srv_recv_api (zns_srv_t *self)
{
    //  Get the whole message of the pipe in one go
    zmsg_t *request = zmsg_recv (self->pipe);
    if (!request)
       return;        //  Interrupted

    char *command = zmsg_popstr (request);
    if (self->verbose)
        zsys_debug ("API command=%s", command);

    if (streq (command, "START"))
        zns_srv_start (self);
    else
    if (streq (command, "STOP"))
        zns_srv_stop (self);
    else
    if (streq (command, "VERBOSE"))
        self->verbose = true;
    else
    if (streq (command, "$TERM")) {
        //  The $TERM command is send by zactor_destroy() method
        zns_srv_stop (self);
        self->terminated = true;
    }
    else
    if (streq (command, "BIND")) {
        char *endpoint = zmsg_popstr (request);
        self->rw_socket = zsock_new_router (endpoint);
        zpoller_add (self->poller, self->rw_socket);
        zstr_free (&endpoint);
    }
    else
    if (streq (command, "DIR")) {
        char *dir = zmsg_popstr (request);
        zns_store_set_dir (self->store, dir);
        zstr_free (&dir);
    }
    else
    if (streq (command, "FILE")) {
        char *file = zmsg_popstr (request);
        zns_store_set_file (self->store, file);
        zstr_free (&file);
    }
    else
    if (streq (command, "PASSWORD")) {
        char *passwd = zmsg_popstr (request);
        zns_srv_set_password (self, passwd);
        zstr_free (&passwd);
    }
    else {
        zsys_error ("invalid API command '%s'", command);
        assert (false);
    }
    zstr_free (&command);
    zmsg_destroy (&request);
}

// receive message from rw socket
static void
s_zns_srv_recv_rw (zns_srv_t *self)
{
    assert (self);
    char *command, *key;
    zmsg_t *msg = zmsg_recv (self->rw_socket);

    zframe_t *routing_id = zmsg_pop (msg);

    command = zmsg_popstr (msg);
    key = zmsg_popstr (msg);

    if (self->verbose)
        zsys_debug ("Proto command=%s %s", command, key);

    if (streq (command, "GET"))
    {
        zchunk_t *chunk = (zchunk_t*) zns_store_get (self->store, key);
        zmsg_t *reply = zmsg_new ();
        zmsg_append (reply, &routing_id);
        zmsg_addstr (reply, command);
        zmsg_addstr (reply, key);
        if (chunk)
            zmsg_addmem (reply, zchunk_data (chunk), zchunk_size (chunk));
        zmsg_send (&reply, self->rw_socket);
    }
    else
    if (streq (command, "PUT"))
    {
        zframe_t *frame = zmsg_pop (msg);
        //TODO: interface with zchunk_t is not the best one ...
        zchunk_t *chunk = zchunk_new (zframe_data (frame), zframe_size (frame));
        zframe_destroy (&frame);
        zns_store_put (self->store, key, chunk);
        zchunk_destroy (&chunk);
    }
    else
        zsys_error ("Invalid command %s", command);

    zstr_free (&key);
    zstr_free (&command);
    zframe_destroy (&routing_id);
    zmsg_destroy (&msg);
}

//  --------------------------------------------------------------------------
//  This is the actor which runs in its own thread.

void
zns_srv_actor (zsock_t *pipe, void *args)
{
    zns_srv_t * self = zns_srv_new (pipe, args);
    if (!self)
        return;          //  Interrupted

    //  Signal actor successfully initiated
    zsock_signal (self->pipe, 0);

    while (!self->terminated) {
        zsock_t *which = (zsock_t *) zpoller_wait (self->poller, 0);
        if (which == self->pipe)
            zns_srv_recv_api (self);
        else
        if (self->rw_socket && which == self->rw_socket)
            s_zns_srv_recv_rw (self);
    }
    zns_srv_destroy (&self);
}


//  --------------------------------------------------------------------------
//  Self test of this actor.

void
zns_srv_test (bool verbose)
{

    printf (" * zns_srv: ");
    zsys_file_delete ("src/test.zenstore");
    zsys_file_delete ("src/test.zenstore.tmp");
    //  @selftest
    //  Simple create/destroy test

    static const char* endpoint = "inproc://@/zns-srv-test";
    static const char* password = "S3cr3t!";

    zactor_t *zns_srv = zactor_new (zns_srv_actor, NULL);

    //TODO - call start/put/get/stop/start/get/get
    zstr_sendx (zns_srv, "BIND", endpoint, NULL);
    zstr_sendx (zns_srv, "DIR", "src", NULL);
    zstr_sendx (zns_srv, "FILE", "test.zenstore", NULL);
    zstr_sendx (zns_srv, "PASSWORD", password, NULL);
    zstr_sendx (zns_srv, "START", NULL);

    zsock_t *sock = zsock_new_dealer (endpoint);
    assert (sock);

    // PUT/GET test
    char *command, *key, *value;

    zstr_sendx (sock, "PUT", "KEY", "VALUE", NULL);
    zstr_sendx (sock, "GET", "KEY", NULL);

    //FIXME: recvx fails on zmsg_is ...
    //zstr_recvx (sock, &command, &key, &value);
    zmsg_t *msg = zmsg_recv (sock);
    command = zmsg_popstr (msg);
    key = zmsg_popstr (msg);
    value = zmsg_popstr (msg);
    zmsg_destroy (&msg);
    assert (streq (command, "GET"));
    assert (streq (key, "KEY"));
    assert (streq (value, "VALUE"));

    zstr_free (&command);
    zstr_free (&key);
    zstr_free (&value);

    // GET - no key
    zstr_sendx (sock, "GET", "NOKEY", NULL);

    msg = zmsg_recv (sock);
    command = zmsg_popstr (msg);
    key = zmsg_popstr (msg);
    value = zmsg_popstr (msg);
    zmsg_destroy (&msg);
    assert (streq (command, "GET"));
    assert (streq (key, "NOKEY"));
    assert (!value);

    zstr_free (&command);
    zstr_free (&key);
    zstr_free (&value);

    zsock_destroy (&sock);

    zactor_destroy (&zns_srv);
    //  @end

    printf ("OK\n");
}
