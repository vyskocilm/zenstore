/*  =========================================================================
    zenstore - Daemon

    Copyright (c) the Contributors as noted in the AUTHORS file.       
                                                                       
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.           
    =========================================================================
*/

/*
@header
    zenstore - Daemon
@discuss
@end
*/

#include "zns_classes.h"

#if defined __UNIX__
#include <termios.h>

// read up to crypto_secretbox_KEYBYTES from tty. Return allocated array or NULL
// if the input is longer, warning is issues and key is stripped down
static byte *
s_getkey ()
{
    // source of "wisdom"
    // http://www.gnu.org/software/libc/manual/html_node/getpass.html
    // http://man7.org/tlpi/code/online/book/tty/no_echo.c.html

    struct termios old, new_;
    byte *ret = NULL;

    /* Turn echoing off and fail if we can’t. */
    int r = tcgetattr (STDOUT_FILENO, &old);
    if (r != 0) {
        zsys_error ("tcgetattr failed: %m");
        return NULL;
    }

    new_ = old;
    new_.c_lflag &= ~ECHO;
    r = tcsetattr (STDIN_FILENO, TCSAFLUSH, &new_);
    if (r != 0) {
        zsys_error ("tcsetattr failed: %m");
        return NULL;
    }

    ret = (byte*) zmalloc (crypto_secretbox_KEYBYTES);
    if (!ret) {
        zsys_error ("Allocating of buffer failed: %m");
        goto end;
    }

    printf ("Enter the password: ");
    fflush (stdout);

    r = (int) read (STDIN_FILENO, ret, crypto_secretbox_KEYBYTES);
    if (r == -1) {
        zsys_error ("read failed: %m");
        goto end;
    }

    for (int i = 0; i != crypto_secretbox_KEYBYTES; i++)
        if (ret [i] == '\n') {
            ret [i] = '\0';
            break;
        }

end:
    /* Restore terminal. */
    (void) tcsetattr (STDIN_FILENO, TCSAFLUSH, &old);

    return ret;
}

#else
#error Please send a pull request with password reading for Windows
#endif

int main (int argc, char *argv [])
{
    bool verbose = false;
    char *endpoint = ZNS_DEFAULT_ENDPOINT;
    char *store_path = NULL;
    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("zenstore [options] ...");
            puts ("  --endpoint / -e        zeromq endpoint to bind");
            puts ("  --store / -s           path to store file");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            return 0;
        }
        else
        if (streq (argv [argn], "--verbose")
        ||  streq (argv [argn], "-v"))
            verbose = true;
        else
        if (streq (argv [argn], "--endpoint")
        ||  streq (argv [argn], "-e")) {
            if (argc == argn+1) {
                printf ("Missing argument for --endpoint/-e\n");
                return -1;
            }
            endpoint = argv [argn+1];
            argn++;
        }
        else
        if (streq (argv [argn], "--store")
        ||  streq (argv [argn], "-s")) {
            if (argc == argn+1) {
                printf ("Missing argument for --store/-s\n");
                return -1;
            }
            store_path = argv [argn+1];
            argn++;
        }
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }

    //  Insert main code here
    if (verbose)
        zsys_info ("zenstore - Daemon\n\tendpoint=%s, store_path=%s", endpoint, store_path);

    byte * password = s_getkey ();
    if (!password) {
        printf ("Reading password failed");
        return -1;
    }

    // start an actor
    zactor_t *zns_srv = zactor_new (zns_srv_actor, NULL);

    // start an actor
    zstr_sendx (zns_srv, "STORE", "src/test.zenstore", NULL);
    zstr_sendx (zns_srv, "PASSWORD", password, NULL);
    free (password);
    password = NULL;
    zstr_sendx (zns_srv, "START", NULL);
    zstr_sendx (zns_srv, "BIND", endpoint, NULL);

    // src/malamute.c under MPL license
    //  Accept and print any message back from server
    while (true) {
        char *message = zstr_recv (zns_srv);
        if (message) {
            puts (message);
            free (message);
        }
        else {
            puts ("interrupted");
            break;
        }
    }
    zactor_destroy (&zns_srv);

    return 0;
}
