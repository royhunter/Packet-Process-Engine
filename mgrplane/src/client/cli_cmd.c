/**
 * \file     test_parser.c
 * \brief    Test program for parser library.
 * \details  This is a test program with a simple CLI that serves as a demo
 *           as well.
 * \version  \verbatim $Id: test_parser.c 33 2009-01-22 06:45:33Z henry $ \endverbatim
 */
/*
 * Copyright (c) 2008-2009, Henry Kwok
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the project nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY HENRY KWOK ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL HENRY KWOK BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "cparser.h"
#include "cparser_token.h"

int interactive = 0;
#define PRINTF(args...)                                 \
    if (interactive) {                                  \
        printf(args);                                   \
    } else {                                            \
        output_ptr += sprintf(output_ptr, args);        \
    }

#define MAX_NAME        (128)
#define MAX_EMPLOYEES   (100)
#define MAX_TITLE       (32)

char *output_ptr;
char output[2000]; /* buffer for sprintf */

/**
 * List all available commands
 */
cparser_result_t
cparser_cmd_help_filter (cparser_context_t *context, char **filter)
{
    assert(context);
    return cparser_help_cmd(context->parser, filter ? *filter : NULL);
}


/**
 * Exit the parser test program.
 */
cparser_result_t
cparser_cmd_quit (cparser_context_t *context)
{
    assert(context);
    return cparser_quit(context->parser);
}



static cparser_result_t
cparser_cmd_enter_privileged_mode (cparser_t *parser, char *buf, int buf_size)
{
    if (strncmp(buf, "HELLO", buf_size)) {
        PRINTF("\nPassword incorrect. Should enter 'HELLO'.\n");
    } else {
        PRINTF("\nEnter privileged mode.\n");
        cparser_set_privileged_mode(parser, 1);
    }
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_enable_privileged_mode (cparser_context_t *context)
{
    char passwd[100];
    int rc;

    assert(context && context->parser);

    if (cparser_is_in_privileged_mode(context->parser)) {
        PRINTF("Already in privileged mode.\n");
        return CPARSER_NOT_OK;
    }

    /* Request privileged mode password */
    rc = cparser_user_input(context->parser, "Enter password (Enter: 'HELLO'): ", 0,
                            passwd, sizeof(passwd), cparser_cmd_enter_privileged_mode);
    assert(CPARSER_OK == rc);
    return CPARSER_OK;
}

cparser_result_t
cparser_cmd_disable_privileged_mode (cparser_context_t *context)
{
    assert(context && context->parser);
    if (!cparser_is_in_privileged_mode(context->parser)) {
        PRINTF("Not in privileged mode.\n");
        return CPARSER_NOT_OK;
    }

    cparser_set_privileged_mode(context->parser, 0);
    return CPARSER_OK;
}

