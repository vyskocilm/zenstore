/*  =========================================================================
    zns_store - Class implementing access to encrypted storage

    Copyright (c) the Contributors as noted in the AUTHORS file.       
    This file is part of zenstore - ZeroMQ based encrypted store.      
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

/*
@header
    zns_store - Class implementing access to encrypted storage
@discuss
@end
*/

#include "zns_classes.h"

//  Structure of our class

struct _zns_store_t {
    bool verbose;
    zhashx_t *hash;
    zns_nonce_t *nonce;
    char *dir;
    char *file;
};

static void
s_destructor (void **self_p)
{
    assert (self_p);
    if (*self_p) {
        zchunk_t *chunk = (zchunk_t*) *self_p;
        zchunk_fill (chunk, 0x00, zchunk_max_size (chunk));
        zchunk_destroy (&chunk);
    }
}

static void*
s_duplicator (const void *self)
{
    assert (self);
    return (void*) zchunk_dup ((zchunk_t*) self);
}

// pack the hashx in form string : zchunk_t
static zframe_t*
s_zhashx_pack (zhashx_t *hash)
{
    assert (hash);
    zmsg_t *msg = zmsg_new ();

    for (void *it = zhashx_first (hash);
               it != NULL;
               it = zhashx_next (hash))
    {
        zmsg_addstr (msg, (char*) zhashx_cursor (hash));
        zchunk_t *chunk = (zchunk_t *) it;
        zmsg_addmem (msg, zchunk_data (chunk), zchunk_size (chunk));
    }

    byte *buffer;
    size_t size = zmsg_encode (msg, &buffer);
    zmsg_destroy (&msg);

    zframe_t *frame = zframe_new (buffer, size);
    free (buffer);
    return frame;
}

//unpack the zhashx (string : zchunk_t)
static zhashx_t*
s_zhashx_unpack (zframe_t *frame)
{
    assert (frame);
    zmsg_t *msg = zmsg_decode (zframe_data (frame), zframe_size (frame));
    if (!msg)
        return NULL;

    // zns_store_new
    zhashx_t *hash = zhashx_new ();
    zhashx_set_destructor (hash, s_destructor);
    zhashx_set_duplicator (hash, s_duplicator);

    while (zmsg_size (msg) > 0)
    {
        char *key = zmsg_popstr (msg);
        zframe_t *frame = zmsg_pop (msg);
        assert (key);
        assert (frame);

        zchunk_t *chunk = zchunk_new (zframe_data (frame), zframe_size (frame));
        zframe_destroy (&frame);

        zhashx_update (hash, key, (void*) chunk);
        zstr_free (&key);
        zchunk_destroy (&chunk);
    }
    zmsg_destroy (&msg);

    return hash;
}

//  --------------------------------------------------------------------------
//  Create a new zns_store

zns_store_t *
zns_store_new (void)
{
    zns_store_t *self = (zns_store_t *) zmalloc (sizeof (zns_store_t));
    assert (self);
    //  Initialize class properties here
    self->hash = zhashx_new ();
    assert (self->hash);
    zhashx_set_destructor (self->hash, s_destructor);
    zhashx_set_duplicator (self->hash, s_duplicator);

    self->nonce = zns_nonce_new ();
    assert (self->nonce);

    self->dir = NULL;
    self->file = NULL;

    return self;
}

//  --------------------------------------------------------------------------
//  Destroy the zns_store

void
zns_store_destroy (zns_store_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        zns_store_t *self = *self_p;
        //  Free class properties here
        zhashx_destroy (&self->hash);
        zns_nonce_destroy (&self->nonce);
        zstr_free (&self->dir);
        zstr_free (&self->file);
        //  Free object itself
        free (self);
        *self_p = NULL;
    }
}

//  --------------------------------------------------------------------------
//  Put the binary chunk with given key to store

void
zns_store_put (zns_store_t *self, const char* key, zchunk_t *value)
{
    assert (self);
    assert (key);
    if (!value)
        zhashx_delete (self->hash, key);
    else
        zhashx_update (self->hash, key, value);
}

//  --------------------------------------------------------------------------
//  Get the reference to the store or NULL if not there - ownership is NOT
//  passed

const zchunk_t *
zns_store_get (zns_store_t *self, const char* key)
{
    assert (self);
    assert (key);
    return (zchunk_t*) zhashx_lookup (self->hash, key);
}

//  --------------------------------------------------------------------------
//  Set directory to store into

void
zns_store_set_dir (zns_store_t *self, const char *dir)
{
    assert (self);
    self->dir = strdup (dir);
}

//  --------------------------------------------------------------------------
//  Set file name inside path

void
zns_store_set_file (zns_store_t *self, const char *file)
{
    assert (self);
    self->file = strdup (file);
}

static int
s_add_header (zns_store_t *self, zmsg_t *msg)
{

    zconfig_t *header = zconfig_new ("header", NULL);
    if (!header)
        return -1;

    zconfig_t *version = zconfig_new ("version", header);
    zconfig_set_value (version, "1");

    zconfig_t *method = zconfig_new ("method", header);
    zconfig_set_value (method, "crypto_secretbox");

    zconfig_t *cipher = zconfig_new ("cipher", header);
    zconfig_set_value (cipher, "salsa20poly1305");

    zconfig_t *nonce = zconfig_new ("nonce", header);
    if (!zns_nonce_initialized (self->nonce))
        zns_nonce_rand (self->nonce);
    char *nonce_str = zns_nonce_str (self->nonce);
    if (self->verbose)
        zsys_debug ("\tnonce_str=%s", nonce_str);
    zconfig_set_value (nonce, nonce_str, NULL);
    zstr_free (&nonce_str);

    zchunk_t *chunk = zconfig_chunk_save (header);
    zconfig_destroy (&header);
    if (!chunk)
        return -1;

    int r = zmsg_addmem (msg, zchunk_data (chunk), zchunk_size (chunk));
    if (self->verbose)
        zsys_debug ("\theader size: %zu", zchunk_size (chunk));
    zchunk_destroy (&chunk);
    return r;
}

static int
s_add_encrypted_hash (zns_store_t *self, zmsg_t *msg, byte key [crypto_secretbox_KEYBYTES])
{
    zframe_t *frame = s_zhashx_pack (self->hash);
    if (!frame)
        return -1;
    if (self->verbose)
        zsys_debug ("\tpacked zhashx size: %zu", zframe_size (frame));

    size_t buffer_size = zframe_size (frame);
    size_t encrypted_buffer_size = crypto_secretbox_MACBYTES + buffer_size;
    byte* encrypted_buffer = (byte*) zmalloc (encrypted_buffer_size);
    if (!encrypted_buffer) {
        zframe_destroy (&frame);
        return -1;
    }

    int r = crypto_secretbox_easy (
            encrypted_buffer,
            zframe_data (frame), buffer_size,
            zns_nonce_raw (self->nonce),
            key);
    sodium_memzero (zframe_data (frame), buffer_size);
    zframe_destroy (&frame);

    if (r != 0) {
        sodium_memzero (encrypted_buffer, encrypted_buffer_size);
        free (encrypted_buffer);
        return -1;
    }

    zmsg_addmem (msg, encrypted_buffer, encrypted_buffer_size);
    if (self->verbose)
        zsys_debug ("\tencrypted buffer size: %zu", encrypted_buffer_size);
    sodium_memzero (encrypted_buffer, encrypted_buffer_size);
    free (encrypted_buffer);
    return 0;
}

static int
s_save (zns_store_t *self, zmsg_t **msg_p)
{
    assert (self);
    assert (msg_p);

    zmsg_t *msg = *msg_p;

    char filename [PATH_MAX];
    //TODO: maybe POSIX API is not the best here :) - lets investigate zfile /zsys_file API
    //TODO O_TMPFILE sounds like an interesting feature here - lets check it
    snprintf (filename, PATH_MAX, "%s/%s.tmp", self->dir, self->file);
    int fd = open (filename, O_CLOEXEC | O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_SYNC | O_TRUNC, 0600);
    if (fd < 0) {
        zsys_error ("Can't create '%s' : %s", filename, strerror (errno));
        zmsg_destroy (&msg);
        return -1;
    }

    byte *buffer;
    size_t buffer_size = zmsg_encode (msg, &buffer);
    if (self->verbose)
        zsys_debug ("\toverall buffer size: %zu", buffer_size);
    zmsg_destroy (&msg);
    //TODO decode error checking

    ssize_t wr = write (fd, buffer, buffer_size);
    if (self->verbose)
        zsys_debug ("\tbytes written to file: %zd", wr);
    sodium_memzero (buffer, buffer_size);
    free (buffer);
    fsync (fd);
    close (fd);

    if (wr != buffer_size) {
        zsys_error ("Written less bytes '%zd' than expected '%zu', removing '%s': %s", wr, buffer_size, filename, strerror (errno));
        unlink (filename);
        return -1;
    }

    char filename_new [PATH_MAX];
    snprintf (filename_new, PATH_MAX, "%s/%s", self->dir, self->file);
    int r = rename (filename, filename_new);
    if (r == -1) {
        zsys_error ("Rename failed: %s", strerror (errno));
        return -1;
    }
    return 0;
}

//  --------------------------------------------------------------------------
//  Save the keystore to path/file, return 0 for success, -1 for error

int zns_store_save (
        zns_store_t *self,
        byte key [crypto_secretbox_KEYBYTES])
{
    assert (self);

    if (!self->dir || !self->file)
        return -1;

    zmsg_t *msg = zmsg_new ();
    if (!msg) {
        return -1;
    }

    int r = s_add_header (self, msg);
    if (r == -1) {
        zmsg_destroy (&msg);
        return -1;
    }

    r = s_add_encrypted_hash (self, msg, key);
    if (r == -1) {
        zmsg_destroy (&msg);
        return -1;
    }

    return s_save (self, &msg);
}

//  --------------------------------------------------------------------------
//  Load the keystore from path/file, return 0 for success, -1 for error

int
zns_store_load (zns_store_t *self, byte key [crypto_secretbox_KEYBYTES])
{
    if (self->verbose)
        zsys_debug ("zns_store_load:");
    assert (self);
    if (!self->dir || !self->file)
        return -1;

    zfile_t *file = zfile_new (self->dir, self->file);
    if (!file)
        return -1;

    if (!zsys_file_exists (zfile_filename (file, NULL))) {
        zsys_error ("file '%s' does not exists", zfile_filename (file, NULL));
        zfile_destroy (&file);
        return -1;
    }

    if (!zsys_file_mode (zfile_filename (file, NULL)) == 0600) {
        zsys_error ("file '%s' must be readable/writable only by user", zfile_filename (file, NULL));
        zfile_destroy (&file);
        return -1;
    }

    int r = zfile_input (file);
    if (r != 0) {
        zsys_error ("Can't open '%s' for reading: %s", zfile_filename (file, NULL), strerror (errno));
        zfile_destroy (&file);
        return -1;
    }

    zfile_restat (file);
    size_t buffer_size = zfile_cursize (file);
    if (self->verbose)
        zsys_debug ("\tfile size: %zu", buffer_size);
    zchunk_t *buffer = zfile_read (file, buffer_size, 0);
    if (self->verbose)
        zsys_debug ("\toverall buffer size: %zu", zchunk_size (buffer));
    const char *error_message = strerror (errno);
    zfile_close (file);
    zfile_destroy (&file);

    if (!buffer) {
        zsys_error ("Read failed: %s", error_message);
        return -1;
    }

    zmsg_t *msg = zmsg_decode (zchunk_data (buffer), zchunk_size (buffer));
    zchunk_destroy (&buffer);
    if (!msg) {
        zsys_error ("Decoding of message have failed");
        return -1;
    }

    // header
    zframe_t *frame = zmsg_pop (msg);
    if (!frame) {
        zsys_error ("Extracting of header failed");
        zmsg_destroy (&msg);
        return -1;
    }
    if (self->verbose)
        zsys_debug ("\tpacked zhashx size: %zu", zframe_size (frame));

    zchunk_t *header_chunk = zchunk_new (zframe_data (frame), zframe_size (frame));
    zframe_destroy (&frame);
    zconfig_t *header = zconfig_chunk_load (header_chunk);
    zchunk_destroy (&header_chunk);
    if (!header) {
        zsys_error ("Decoding of header failed");
        zconfig_destroy (&header);
        zmsg_destroy (&msg);
        return -1;
    }

    // check the content of header zconfig
    if (!streq (zconfig_get (header, "version", ""), "1")) {
        zsys_error ("Unsupported version, got '%s', expected '1'", zconfig_get (header, "version", ""));
        zconfig_destroy (&header);
        zmsg_destroy (&msg);
        return -1;
    }

    if (!streq (zconfig_get (header, "method", ""), "crypto_secretbox")) {
        zsys_error ("Unsupported method, got '%s', expected 'crypto_secretbox'", zconfig_get (header, "method", ""));
        zconfig_destroy (&header);
        zmsg_destroy (&msg);
        return -1;
    }

    if (!streq (zconfig_get (header, "cipher", ""), "salsa20poly1305")) {
        zsys_error ("Unsupported cipher, got '%s', expected 'salsa20poly1305'", zconfig_get (header, "cipher", ""));
        zconfig_destroy (&header);
        zmsg_destroy (&msg);
        return -1;
    }

    if (streq (zconfig_get (header, "nonce", "<nonce>"), "<nonce>")) {
        zsys_error ("Missing nonce, got '%s', expected nonce", zconfig_get (header, "nonce", ""));
        zconfig_destroy (&header);
        zmsg_destroy (&msg);
        return -1;
    }

    r = zns_nonce_from_str (self->nonce, zconfig_get (header, "nonce", ""));
    zconfig_destroy (&header);
    if (r == -1) {
        zsys_error ("Can't decode nonce: '%s'", zconfig_get (header, "nonce", ""));
        zmsg_destroy (&msg);
        return -1;
    }
    if (self->verbose) {
        char *nonce_str = zns_nonce_str (self->nonce);
        zsys_debug ("\tnonce_str=%s", nonce_str);
        zstr_free (&nonce_str);
    }

    frame = zmsg_pop (msg);
    if (!frame) {
        zsys_error ("Can't read encrypted data frame");
        zmsg_destroy (&msg);
        return -1;
    }
    if (self->verbose)
        zsys_debug ("\tencrypted buffer size: %zu", zframe_size (frame));

    size_t decrypted_buffer_size = zframe_size (frame) - crypto_secretbox_MACBYTES;
    zchunk_t *decrypted_buffer = zchunk_new (NULL, decrypted_buffer_size);
    //FIXME: this is incorrect use of zchunk, zchunk_size does not report properly
    r = crypto_secretbox_open_easy(
            zchunk_data (decrypted_buffer),
            zframe_data (frame),
            zframe_size (frame),
            zns_nonce_raw (self->nonce),
            key);

    sodium_memzero (zframe_data (frame), zframe_size (frame));
    zframe_destroy (&frame);
    zconfig_destroy (&header);
    zmsg_destroy (&msg);

    if (r != 0) {
        zsys_error ("Decrypting of storage failed");
        sodium_memzero (zchunk_data (decrypted_buffer), zchunk_max_size (decrypted_buffer));
        zchunk_destroy (&decrypted_buffer);

    }

    frame = zframe_new (zchunk_data (decrypted_buffer), decrypted_buffer_size);
    if (self->verbose)
        zsys_debug ("\tpacked zhashx size: %zu", zframe_size (frame));
    sodium_memzero (zchunk_data (decrypted_buffer), zchunk_max_size (decrypted_buffer));
    zchunk_destroy (&decrypted_buffer);

    zhashx_t *hash = s_zhashx_unpack (frame);

    sodium_memzero (zframe_data (frame), zframe_size (frame));
    zframe_destroy (&frame);

    if (!hash) {
        zsys_error ("Unpacking of storage failed");
        return -1;
    }

    zhashx_destroy (&self->hash);
    self->hash = hash;
    return 0;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
zns_store_test (bool verbose)
{
    printf (" * zns_store: ");
    zsys_file_delete ("src/test.zenstore");
    zsys_file_delete ("src/test.zenstore.tmp");

    //  @selftest
    zns_store_t *store = zns_store_new ();

    // PUT / GET test
    zchunk_t *chunk = zchunk_new ("CHUNK", strlen ("CHUNK") + 1);
    zns_store_put (store, "KEY", chunk);
    zchunk_destroy (&chunk);

    assert (zns_store_get (store, "KEY"));
    assert (!zns_store_get (store, "NO-KEY"));

    // store test
    zns_store_set_dir (store, "src");
    zns_store_set_file (store, "test.zenstore");

    int r = zns_store_save (store, (byte*) "S3cret!");
    assert (r == 0);
    zns_store_destroy (&store);
    assert (!store);

    // load test
    store = zns_store_new ();
    zns_store_set_dir (store, "src");
    zns_store_set_file (store, "test.zenstore");

    r = zns_store_load (store, (byte*) "S3cret!");
    assert (r == 0);

    assert (zns_store_get (store, "KEY"));
    zns_store_destroy (&store);

    //  @end
    printf ("OK\n");
}
