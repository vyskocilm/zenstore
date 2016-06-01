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
    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq (argv [argn], "--help")
        ||  streq (argv [argn], "-h")) {
            puts ("zenstore [options] ...");
            puts ("  --verbose / -v         verbose test output");
            puts ("  --help / -h            this information");
            return 0;
        }
        else
        if (streq (argv [argn], "--verbose")
        ||  streq (argv [argn], "-v"))
            verbose = true;
        else {
            printf ("Unknown option: %s\n", argv [argn]);
            return 1;
        }
    }
    //  Insert main code here
    if (verbose)
        zsys_info ("zenstore - Daemon");

    byte * key = s_getkey ();
    zstr_free (&key);
    return 0;
}
