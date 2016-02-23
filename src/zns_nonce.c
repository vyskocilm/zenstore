/*  =========================================================================
    zns_nonce - Class wrapping array buffers

    Copyright (c) the Contributors as noted in the AUTHORS file.       
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

/*
@header
    zns_nonce - Class wrapping array buffers
@discuss
@end
*/

#include "zns_classes.h"

//  Structure of our class

struct _zns_nonce_t {
    byte nonce [crypto_secretbox_NONCEBYTES];     //  Declare class properties here
};


//  --------------------------------------------------------------------------
//  Create a new zns_nonce

zns_nonce_t *
zns_nonce_new (void)
{
    zns_nonce_t *self = (zns_nonce_t *) zmalloc (sizeof (zns_nonce_t));
    assert (self);
    //  Initialize class properties here
    sodium_memzero (self->nonce, sizeof self->nonce);
    return self;
}

//  --------------------------------------------------------------------------
//  Check if nonce is initialized or zero

bool
zns_nonce_initialized (zns_nonce_t* self)
{
    assert (self);
    for (size_t i = 0; i != sizeof self->nonce; i++)
        if (self->nonce [i] != 0x00 )
            return true;
    return false;
}

//  --------------------------------------------------------------------------
//  Generate random nonce using libsodium routines

void
zns_nonce_rand (zns_nonce_t *self)
{
    assert (self);
    randombytes_buf (self->nonce, sizeof self->nonce);
}

//  --------------------------------------------------------------------------
//  Convert the nonce to hexadecimal representation compatible with C strings
//  including ending \0. Caller is responsible for free'ing the memory.

char*
zns_nonce_str (zns_nonce_t *self)
{
    assert (self);
    size_t nonce_str_len = sizeof self->nonce * 2 + 1;
    char *nonce_str = (char*) malloc (nonce_str_len);
    assert (nonce_str);

    char *r = sodium_bin2hex (nonce_str, nonce_str_len,
            self->nonce, sizeof self->nonce);

    if (!r) {
        zstr_free (&nonce_str);
        return NULL;
    }
    return nonce_str;
}

//  --------------------------------------------------------------------------
//  Setup the nonce from hexadecimal representation (see zns_nonce_str).

int
zns_nonce_from_str (zns_nonce_t *self, const char* nonce_str)
{
    assert (self);
    size_t nonce_str_len = strlen (nonce_str);
    if (nonce_str_len >= sizeof self->nonce * 2 + 1)
        return -1;

    int r = sodium_hex2bin (self->nonce, sizeof self->nonce,
            nonce_str, nonce_str_len,
            NULL, NULL, NULL);

    return r;
}

//  --------------------------------------------------------------------------
//  Return raw representation of nonce.
//  WARNING: this gives you an access to internal buffer, DO NOT MESS WITH IT!

const byte*
zns_nonce_raw (zns_nonce_t *self)
{
    assert (self);
    return self->nonce;
}

//  --------------------------------------------------------------------------
//  Destroy the zns_nonce

void
zns_nonce_destroy (zns_nonce_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        zns_nonce_t *self = *self_p;
        //  Free class properties here
        sodium_memzero (self->nonce, sizeof self->nonce);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Self test of this class

void
zns_nonce_test (bool verbose)
{
    printf (" * zns_nonce: ");

    //  @selftest
    //  Simple create/destroy test
    zns_nonce_t *self = zns_nonce_new ();
    assert (self);

    assert (!zns_nonce_initialized (self));

    zns_nonce_rand (self);
    assert (zns_nonce_initialized (self));

    char *nonce = zns_nonce_str (self);
    assert (nonce);

    zns_nonce_t *nonce2 = zns_nonce_new ();
    assert (nonce2);
    int r = zns_nonce_from_str (nonce2, nonce);
    assert (r != -1);

    assert (memcmp (
                zns_nonce_raw (self),
                zns_nonce_raw (nonce2),
                crypto_secretbox_NONCEBYTES) == 0);

    zns_nonce_destroy (&nonce2);
    zstr_free (&nonce);
    zns_nonce_destroy (&self);
    //  @end
    printf ("OK\n");
}
