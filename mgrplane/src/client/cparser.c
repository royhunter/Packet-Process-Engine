/**
 * \file     cparser.c
 * \brief    parser top-level API
 * \version  \verbatim $Id: cparser.c 159 2011-10-29 09:29:58Z henry $ \endverbatim
 */
/*
 * Copyright (c) 2008-2009, 2011, Henry Kwok
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
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "cparser_io.h"
#include "cparser_fsm.h"

void
cparser_print_prompt (const cparser_t *parser)
{
    assert(parser);
    if (cparser_is_in_privileged_mode(parser)) {
        parser->cfg.printc(parser, '+');
    }
    parser->cfg.prints(parser, parser->prompt[parser->root_level]);
}

/**
 * \brief    Print the description of a node out.
 * \details  For keyword nodes,  the keyword itself is printed. For parameter
 *           nodes, a string of the form <[type]:[parameter]> is printed. For
 *           end nodes, \<LF\> is printed. This call should never be invoked with
 *           a root node.
 *
 * \param    parser     Pointer to the parser structure.
 * \param    node       Pointer to the node to be printed.
 * \param    add_lf     1 to add LF before printing the node; 0 otherwise.
 * \param    print_desc 1 to print the description of the node; 0 otherwise.
 */
static void
cparser_help_print_node (cparser_t *parser, cparser_node_t *node,
                         const int add_lf, const int print_desc)
{
    assert(parser && node);
    if (!NODE_USABLE(parser, node)) {
        return;
    }
    if (add_lf) {
        parser->cfg.printc(parser, '\n');
    }
    switch (node->type) {
        case CPARSER_NODE_ROOT:
            assert(0); /* this should never happen */
        case CPARSER_NODE_END:
            parser->cfg.prints(parser, "<LF>");
            break;
        case CPARSER_NODE_LIST:
            parser->cfg.prints(parser, "[ ");
            cparser_list_node_t *lnode = (cparser_list_node_t *)node->param;
            assert(lnode);
            while (lnode) {
                parser->cfg.prints(parser, lnode->keyword);
                lnode = lnode->next;
                if (lnode) {
                    parser->cfg.prints(parser, " | ");
                }
            }
            parser->cfg.prints(parser, " ]");
            break;
        default:
            parser->cfg.prints(parser, node->param);
            if (print_desc && node->desc) {
                parser->cfg.prints(parser, " - ");
                parser->cfg.prints(parser, node->desc);
            }
            break;
    }
}

/**
 * \brief    Print an error message due to some kind of parsing error.
 *
 * \param    parser Pointer to the parser structure.
 * \param    msg    Pointer to the error messsage string.
 *
 * \return   None.
 */
static void
cparser_print_error (cparser_t *parser, const char *msg)
{
    int n, m;

    assert(parser && msg);

    parser->cfg.printc(parser, '\n');
    m = strlen(parser->prompt[parser->root_level]) + 1;
    for (n = 0; n < m+parser->last_good; n++) {
        parser->cfg.printc(parser, ' ');
    }
    parser->cfg.printc(parser, '^');
    parser->cfg.prints(parser, msg);
}

/**
 * \brief    Reset the user input section of the parser structure.
 *
 * \param    parser Pointer to the parser structure.
 */
static void
cparser_input_reset (cparser_t *parser)
{
    assert(parser);
    parser->user_buf = NULL;
    parser->user_buf_size = 0;
    parser->user_buf_count = 0;
    parser->user_input_cb = NULL;
}

int
cparser_is_user_input (cparser_t *parser, int *do_echo)
{
    assert(parser && do_echo);
    if (parser->user_buf) {
        assert(parser->user_input_cb && parser->user_buf_size);
        *do_echo = parser->user_do_echo;
        return 1;
    }
    assert(!parser->user_input_cb && !parser->user_buf_size);
    *do_echo = 0;
    return 0;
}

static void
cparser_record_command (cparser_t *parser, cparser_result_t rc)
{
    assert(parser);

    /* Save the state of the command */
    parser->last_line_idx = CURRENT_LINE(parser);
    parser->last_rc = rc;
    parser->last_end_node = parser->cur_node;
}

/**
 * \brief    If the command is not complete, attempt to complete the command.
 *           If there is a complete comamnd, execute the glue (& action)
 *           function of a command.
 *
 * \param    parser Pointer to the parser structure.
 *
 * \return   CPARSER_OK if a valid command is executed; CPARSER_NOT_OK
 *           otherwise.
 */
static cparser_result_t
cparser_execute_cmd (cparser_t *parser)
{
    int do_echo;
    cparser_result_t rc = CPARSER_OK;
    assert(VALID_PARSER(parser));

    /*
     * Enter a command. There are three possibilites:
     * 1. If we are in WHITESPACE state, we check if there is
     *    only one child of keyword type. If yes, we recurse
     *    into it and repeat until either: a) there is more than
     *    one choice, b) We are at a END node. If there is more
     *    than one choice, we look for an END node. In either
     *    case, if an END node is found, we execute the action
     *    function.
     *
     * 2. If we are in TOKEN state, we check if we have an unique
     *    match. If yes, re recurse into it and repeat just
     *    like WHITESPACE state until we find an END node.
     *
     * 3. If we are in ERROR state, we print out an error.
     *
     * Afterward, we reset the parser state and move to the
     * next line buffer.
     */
    if ((CPARSER_STATE_TOKEN == parser->state) ||
        (CPARSER_STATE_WHITESPACE == parser->state)) {
        cparser_node_t *child;

        if (CPARSER_STATE_TOKEN == parser->state) {
            cparser_token_t *token;
            cparser_node_t *match;
            int is_complete;

            token = CUR_TOKEN(parser);
            if ((1 <= cparser_match(parser, token->buf, token->token_len,
                                    parser->cur_node, &match,
                                    &is_complete)) &&
                (is_complete)) {
                cparser_complete_fn fn = cparser_complete_fn_tbl[match->type];
                if (fn) {
                    fn(parser, match, token->buf, token->token_len);
                }
                rc = cparser_input(parser, ' ', CPARSER_CHAR_REGULAR);
                assert(CPARSER_OK == rc);
            } else {
                cparser_print_error(parser, "Incomplete command\n");
                rc = CPARSER_ERR_INCOMP_CMD;

                /* Reset the internal buffer, state and cur_node */
                cparser_record_command(parser, rc);
                cparser_fsm_reset(parser);
                cparser_print_prompt(parser);
                return rc;
            }
        }

        /* Look for a single keyword node child */
        child = parser->cur_node->children;
        assert(child);
        while ((CPARSER_NODE_KEYWORD == child->type) &&
               NODE_USABLE(parser, child) && (!child->sibling)) {
            cparser_token_t *token = CUR_TOKEN(parser);
            cparser_complete_keyword(parser, child, token->buf, token->token_len);
            rc = cparser_input(parser, ' ', CPARSER_CHAR_REGULAR);
            assert(CPARSER_OK == rc);

            child = parser->cur_node->children;
            assert(child);
        }

        /* Look for an end node */
        child = parser->cur_node->children;
        while ((NULL != child) &&
               !((CPARSER_NODE_END == child->type) && NODE_USABLE(parser, child))) {
            child = child->sibling;
        }
        if (child) {
            assert(CPARSER_NODE_END == child->type);

            /* Execute the glue function */
            parser->cur_node = child;
            parser->cfg.printc(parser, '\n');
            rc = ((cparser_glue_fn)child->param)(parser);
        } else {
            if (parser->token_tos) {
                cparser_print_error(parser, "Incomplete command\n");
                rc = CPARSER_ERR_INCOMP_CMD;
            }

            /* Reset FSM states and advance to the next line */
            cparser_record_command(parser, rc);
            cparser_fsm_reset(parser);
            if (CPARSER_OK == rc) {
                /* This is just a blank line */
                parser->cfg.printc(parser, '\n');
            }
            cparser_print_prompt(parser);
            return rc;
        }
    } else if (CPARSER_STATE_ERROR == parser->state) {
        cparser_print_error(parser, "Parse error\n");
        rc = CPARSER_ERR_PARSE_ERR;
    }

    /* Reset FSM states and advance to the next line */
    cparser_record_command(parser, rc);
    cparser_fsm_reset(parser);
    if (!cparser_is_user_input(parser, &do_echo)) {
        cparser_print_prompt(parser);
    }
    return rc;
}

static cparser_result_t
cparser_match_prefix (const cparser_t *parser, const char *token,
                      const int token_len, const cparser_node_t *parent,
                      const char ch, const int offset)
{
    int local_is_complete;
    cparser_node_t *child;
    cparser_result_t rc;

    assert(parent && ch);
    for (child = parent->children; NULL != child; child = child->sibling) {
        if (!NODE_USABLE(parser, child)) {
            continue;
        }
        rc = cparser_match_fn_tbl[child->type](token, token_len, child,
                                               &local_is_complete);
        if (CPARSER_NOT_OK == rc) {
            continue;
        }
        if (CPARSER_NODE_KEYWORD != child->type) {
            return CPARSER_NOT_OK;
        }

        /* There is a match. Make sure that it is part of this node as well */
        if (*((char *)child->param + offset) != ch) {
            return CPARSER_NOT_OK;
        }
    }
    return CPARSER_OK;
}

/**
 * \brief    Generate context-sensitive help.
 *
 * \param    parser Pointer to the parser structure.
 */
static cparser_result_t
cparser_help (cparser_t *parser)
{
    cparser_node_t *node;
    cparser_token_t *token;
    int local_is_complete;

    assert(VALID_PARSER(parser));
    if (CPARSER_STATE_WHITESPACE == parser->state) {
        /* Just print out every children */
        for (node = parser->cur_node->children; NULL != node;
             node = node->sibling) {
            cparser_help_print_node(parser, node, 1, 1);
        }
    } else if (CPARSER_STATE_ERROR == parser->state) {
        /*
         * We have some problem parsing. Just print out the last known
         * good parse point and list the valid options.
         */
        cparser_print_error(parser, "Last known good parse point.");
        for (node = parser->cur_node->children; NULL != node;
             node = node->sibling) {
            cparser_help_print_node(parser, node, 1, 1);
        }
    } else {
        /* We have a partial match */
        node = parser->cur_node->children;
        token = CUR_TOKEN(parser);
        for (node = parser->cur_node->children; NULL != node;
             node = node->sibling) {
            if (!NODE_USABLE(parser, node)) {
                continue;
            }
            if (CPARSER_OK ==
                cparser_match_fn_tbl[node->type](token->buf, token->token_len,
                                                 node, &local_is_complete)) {
                cparser_help_print_node(parser, node, 1, 1);
            }
        }
    }
    cparser_line_print(parser, 1, 1);
    return CPARSER_OK;
}

/**
 * \brief    Complete one level in the parse tree.
 * \details  There are serveral cases we will complete one level:
 *
 *           1. If in TOKEN state, the token is unique and complete.
 *           2. If in WHITESPACE state, there is only one child and it
 *              is not a LF.
 */
static int
cparser_complete_one_level (cparser_t *parser)
{
    cparser_token_t *token;
    cparser_node_t *match;
    int is_complete = 0, num_matches, keep_going = 0, rc;
    char *ch_ptr;

    switch (parser->state) {
        case CPARSER_STATE_ERROR:
            /* If we are in ERROR, there cannot be a match. So, just quit */
            parser->cfg.printc(parser, '\a');
            break;
        case CPARSER_STATE_WHITESPACE:
            if (parser->cur_node && parser->cur_node->children &&
                !parser->cur_node->children->sibling &&
                (CPARSER_NODE_KEYWORD == parser->cur_node->children->type)) {
                ch_ptr = parser->cur_node->children->param;
                while (*ch_ptr) {
                    rc = cparser_input(parser, *ch_ptr, CPARSER_CHAR_REGULAR);
                    assert(CPARSER_OK == rc);
                    ch_ptr++;
                }
                rc = cparser_input(parser, ' ', CPARSER_CHAR_REGULAR);
                assert(CPARSER_OK == rc);
            } else {
                /*
                 * If we are in WHITESPACE, just dump all children. Since there is no
                 * way any token can match to a NULL string.
                 */
                cparser_help(parser);
            }
            break;
        case CPARSER_STATE_TOKEN:
        {
            /* Complete a command */
            token = CUR_TOKEN(parser);
            num_matches = cparser_match(parser, token->buf, token->token_len,
                                        parser->cur_node, &match,
                                        &is_complete);
            if ((1 == num_matches) && (is_complete)) {
                cparser_complete_fn fn = cparser_complete_fn_tbl[match->type];
                /*
                 * If the only matched node is a keyword, we feel the rest of
                 * keyword in. Otherwise, we assume this parameter is complete
                 * and just insert a space.
                 */
                if (fn) {
                    fn(parser, match, token->buf, token->token_len);
                }
                rc = cparser_input(parser, ' ', CPARSER_CHAR_REGULAR);
                assert(CPARSER_OK == rc);

                keep_going = 1;
            } else {
                int offset, orig_offset;
                /*
                 * If we have more than one match, we should try to complete
                 * as much as possible. To do that, we grab the node in the
                 * (first) matched node and check that the next character
                 * from it is common among all matched nodes. If it is common
                 * to all matched nodes, we continue to feed them into the
                 * parser. However, this is only useful for keywords. If there
                 * is a parameter token in the match, we automatically abort.
                 */
                offset = orig_offset = token->token_len;
                ch_ptr = match->param + token->token_len;
                while (('\0' != *ch_ptr) &&
                       (CPARSER_OK ==
                        cparser_match_prefix(parser, token->buf, token->token_len,
                                             parser->cur_node, *ch_ptr,
                                             offset))) {
                    rc = cparser_input(parser, *ch_ptr, CPARSER_CHAR_REGULAR);
                    assert(CPARSER_OK == rc);
                    ch_ptr++;
                    offset++;
                }
                if (orig_offset == offset) {
                    /* If there is no common prefix at all, just display help */
                    cparser_help(parser);
                }
            }
            break;
        }
        default: assert(0);
    }

    return keep_going;
}

cparser_result_t
cparser_input (cparser_t *parser, char ch, cparser_char_t ch_type)
{
    int n, do_echo;
    cparser_result_t rc;

    if (!VALID_PARSER(parser)) {
        return CPARSER_ERR_INVALID_PARAMS;
    }

    if (cparser_is_user_input(parser, &do_echo)) {
        /* Process user input */
        if (CPARSER_CHAR_REGULAR != ch_type) {
            return CPARSER_OK;
        }
        if ('\n' == ch) {
            /* We have a complete input. Call the callback. */
            assert(parser->user_input_cb);
            parser->user_buf[parser->user_buf_count] = '\0';
            rc = parser->user_input_cb(parser, parser->user_buf,
                                       parser->user_buf_count);
            cparser_input_reset(parser);
            cparser_print_prompt(parser);
            return rc;
        }

        if ((parser->cfg.ch_erase == ch) || (parser->cfg.ch_del == ch)) {
            if (parser->user_buf_count > 0) {
                parser->user_buf_count--;
            }
            if (parser->user_do_echo) {
                parser->cfg.printc(parser, '\b');
            }
        } else if ((parser->user_buf_count + 1) < parser->user_buf_size) {
            parser->user_buf[parser->user_buf_count] = ch;
            parser->user_buf_count++;
            if (parser->user_do_echo) {
                parser->cfg.printc(parser, ch);
            }
        }
        return CPARSER_OK;
    }

    switch (ch_type) {
        case CPARSER_CHAR_REGULAR:
        {
            if ((parser->cfg.ch_complete == ch) ||
                (parser->cfg.ch_help == ch)) {
                /*
                 * Completion and help character do not go into the line
                 * buffer. So, do nothing.
                 */
                break;
            }
            if ((parser->cfg.ch_erase == ch) || (parser->cfg.ch_del == ch)) {
                rc = cparser_line_delete(parser);
                assert(CPARSER_ERR_INVALID_PARAMS != rc);
                if (CPARSER_ERR_NOT_EXIST == rc) {
                    return CPARSER_OK;
                }
            } else if ('\n' == ch) {
                /* Put the rest of the line into parser FSM */
                for (n = cparser_line_current(parser);
                     n < cparser_line_last(parser); n++) {
                    rc = cparser_fsm_input(parser, cparser_line_char(parser, n));
                    assert(CPARSER_OK == rc);
                }
            } else {
                (void)cparser_line_insert(parser, ch);
            }
            break;
        }
        case CPARSER_CHAR_UP_ARROW:
        {
            rc = cparser_line_prev_line(parser);
            assert(CPARSER_OK == rc);

            /* Reset the token stack and re-enter the command */
            cparser_fsm_reset(parser);
            for (n = 0; n < cparser_line_current(parser); n++) {
                rc = cparser_fsm_input(parser, cparser_line_char(parser, n));
                assert(CPARSER_OK == rc);
            }

            return CPARSER_OK;
        }
        case CPARSER_CHAR_DOWN_ARROW:
        {
            rc = cparser_line_next_line(parser);
            assert(CPARSER_OK == rc);

            /* Reset the token stack and re-enter the command */
            cparser_fsm_reset(parser);
            for (n = 0; n < cparser_line_current(parser); n++) {
                rc = cparser_fsm_input(parser, cparser_line_char(parser, n));
                assert(CPARSER_OK == rc);
            }

            return CPARSER_OK;
        }
        case CPARSER_CHAR_LEFT_ARROW:
        {
            ch = cparser_line_prev_char(parser);
            if (!ch) {
                parser->cfg.printc(parser, '\a');
                return CPARSER_OK;
            }
            break;
        }
        case CPARSER_CHAR_RIGHT_ARROW:
        {
            ch = cparser_line_next_char(parser);
            if (!ch) {
                parser->cfg.printc(parser, '\a');
                return CPARSER_OK;
            }
            break;
        }
        case CPARSER_CHAR_FIRST:
        {
            do {
                ch = cparser_line_prev_char(parser);
                if (ch) {
                    cparser_fsm_input(parser, ch);
                }
            } while (ch);
            return CPARSER_OK;
        }
        case CPARSER_CHAR_LAST:
        {
            do {
                ch = cparser_line_next_char(parser);
                if (ch) {
                    cparser_fsm_input(parser, ch);
                }
            } while (ch);
            return CPARSER_OK;
        }
        default:
        {
            /* An unknown character. Alert and continue */
            parser->cfg.printc(parser, '\a');
            return CPARSER_NOT_OK;
        }
    } /* switch (ch_type) */

    /* Handle special characters */
    if (ch == parser->cfg.ch_complete) {
        while (cparser_complete_one_level(parser));
        return CPARSER_OK;
    } else if (ch == parser->cfg.ch_help) {
        /* Ask for context sensitve help */
        cparser_help(parser);
        return CPARSER_OK;
    } else if ('\n' == ch) {
        rc = cparser_execute_cmd(parser);
        cparser_line_advance(parser);
        return rc;
    }

    return cparser_fsm_input(parser, (char)ch);
}

cparser_result_t
cparser_run (cparser_t *parser)
{
    int ch;
    cparser_char_t ch_type = 0;

    if (!VALID_PARSER(parser)) return CPARSER_ERR_INVALID_PARAMS;

    parser->cfg.io_init(parser);
    cparser_print_prompt(parser);
    parser->done = 0;

    while (!parser->done) {
        parser->cfg.getch(parser, &ch, &ch_type);
        cparser_input(parser, ch, ch_type);
    } /* while not done */

    parser->cfg.prints(parser, "\n");
    
    parser->cfg.io_cleanup(parser);

    return CPARSER_OK;
}

cparser_result_t
cparser_init (cparser_cfg_t *cfg, cparser_t *parser)
{
    int n;

    if (!parser || !cfg || !cfg->root || !cfg->ch_erase) {
    return CPARSER_ERR_INVALID_PARAMS;
    }

    parser->cfg = *cfg;
    parser->cfg.prompt[CPARSER_MAX_PROMPT-1] = '\0';

    /* Initialize sub-mode states */
    parser->root_level = 0;
    parser->root[0] = parser->cfg.root;
    snprintf(parser->prompt[0], sizeof(parser->prompt[0]), "%s",
             parser->cfg.prompt);
    for (n = 0; n < CPARSER_MAX_NESTED_LEVELS; n++) {
        parser->context.cookie[n] = NULL;
    }
    parser->context.parser = parser;

    /* Initialize line buffering states */
    parser->max_line = 0;
    parser->cur_line = 0;
    for (n = 0; n < CPARSER_MAX_LINES; n++) {
        cparser_line_reset(&parser->lines[n]);
    }

    /* Initialize parser FSM state */
    cparser_fsm_reset(parser);
    parser->is_privileged_mode = 0;

    /* Clear the user input state */
    cparser_input_reset(parser);

    return CPARSER_OK;
}

cparser_result_t
cparser_quit (cparser_t *parser)
{
    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    parser->done = 1;
    return CPARSER_OK;
}

cparser_result_t
cparser_submode_enter (cparser_t *parser, void *cookie, char *prompt)
{
    cparser_node_t *new_root;

    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    if ((CPARSER_MAX_NESTED_LEVELS-1) == parser->root_level) {
        return CPARSER_NOT_OK;
    }
    parser->root_level++;
    new_root = parser->cur_node->children;
    assert(new_root);
    assert(CPARSER_NODE_ROOT == new_root->type);
    parser->root[parser->root_level] = new_root;
    snprintf(parser->prompt[parser->root_level],
             sizeof(parser->prompt[parser->root_level]), "%s", prompt);
    parser->context.cookie[parser->root_level] = cookie;

    return CPARSER_OK;
}

cparser_result_t
cparser_submode_exit (cparser_t *parser)
{
    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    if (!parser->root_level) {
        return CPARSER_NOT_OK;
    }
    parser->root_level--;
    return CPARSER_OK;
}

cparser_result_t
cparser_load_cmd (cparser_t *parser, char *filename)
{
    FILE *fp;
    char buf[128];
    size_t rsize, n;
    int fd, indent = 0, last_indent = -1, new_line = 1, m, line_num = 0;

    if (!VALID_PARSER(parser) || !filename) {
        return CPARSER_ERR_INVALID_PARAMS;
    }

    fd = parser->cfg.fd;
    parser->cfg.fd = -1;

    fp = fopen(filename, "r");
    if (!fp) {
        return CPARSER_NOT_OK;
    }

    cparser_fsm_reset(parser);
    while (!feof(fp)) {
        rsize = fread(buf, 1, sizeof(buf), fp);
        for (n = 0; n < rsize; n++) {
            /* Examine the input characters to maintain indent level */
            if ('\n' == buf[n]) {
                cparser_result_t rc;
                char buf[128];

                line_num++;
                indent = 0;
                new_line = 1;
                rc = cparser_execute_cmd(parser);
                if (CPARSER_OK == rc) {
                    continue;
                }
                parser->cfg.fd = fd;
                switch (rc) {
                case CPARSER_ERR_PARSE_ERR:
                    snprintf(buf, sizeof(buf), "Line %d: Parse error.\n", line_num);
                    parser->cfg.prints(parser, buf);
                    break;
                case CPARSER_ERR_INCOMP_CMD:
                    snprintf(buf, sizeof(buf), "Line %d: Incomplete command.\n", line_num);
                    parser->cfg.prints(parser, buf);
                    break;
                default:
                    assert(0);
                }
                return CPARSER_NOT_OK;
            } else if (' ' == buf[n]) {
                if (new_line) {
                    indent++;
                }
            } else {
                if (new_line) {
                    new_line = 0;
                    if (indent < last_indent) {
                        for (m = indent; m < last_indent; m++) {
                            if (CPARSER_OK != cparser_submode_exit(parser)) {
                                break;
                            }
                            cparser_fsm_reset(parser);
                        }
                    }
                    last_indent = indent;
                }
            }
            (void)cparser_fsm_input(parser, buf[n]);
        }
    }
    fclose(fp);

    while (parser->root_level) {
        (void)cparser_submode_exit(parser);
        cparser_fsm_reset(parser);
    }
    parser->cfg.fd = fd;
    return CPARSER_OK;
}

static cparser_result_t
cparser_walk_internal (cparser_t *parser, cparser_node_t *node,
                       cparser_walker_fn pre_fn, cparser_walker_fn post_fn,
                       void *cookie)
{
    cparser_result_t rc;
    cparser_node_t *cur_node;

    if (pre_fn) {
        rc = pre_fn(parser, node, cookie);
        if (CPARSER_OK != rc) {
            return rc;
        }
    }

    if (CPARSER_NODE_END != node->type) {
        cur_node = node->children;
        while (cur_node) {
            cparser_walk_internal(parser, cur_node, pre_fn, post_fn, cookie);
            cur_node = cur_node->sibling;
        }
    }

    if (post_fn) {
        rc = post_fn(parser, node, cookie);
        if (CPARSER_OK != rc) {
            return rc;
        }
    }

    return CPARSER_OK;
}

cparser_result_t
cparser_walk (cparser_t *parser, cparser_walker_fn pre_fn,
              cparser_walker_fn post_fn, void *cookie)
{
    if (!VALID_PARSER(parser) || (!pre_fn && !post_fn)) {
        return CPARSER_ERR_INVALID_PARAMS;
    }

    return cparser_walk_internal(parser, parser->root[parser->root_level],
                                 pre_fn, post_fn, cookie);
}

typedef struct help_stack_ {
    char *filter;
    int  tos;
    cparser_node_t *nodes[CPARSER_MAX_NUM_TOKENS+2];
} help_stack_t;

/**
 * \brief    Pre-order walker function used by cparser_help_cmd().
 * \details  Its main function is to push into the help stack when recurse into
 *           the next level.
 *
 * \param    parser Pointer to the parser structure.
 * \param    node   Pointer to the current parse tree node.
 * \param    cookie Pointer to the help stack.
 *
 * \return   Return CPARSER_OK always.
 */
static cparser_result_t
cparser_help_pre_walker (cparser_t *parser, cparser_node_t *node, void *cookie)
{
    help_stack_t *hs = (help_stack_t *)cookie;

    assert(parser && node && hs);
    hs->nodes[hs->tos] = node;
    hs->tos++;

    return CPARSER_OK;
}

/**
 * \brief    Post-order walker function used by cparser_help_cmd().
 * \details  Its main function is to print out a command description and to
 *           pop the help stack.
 *
 * \param    parser Pointer to the parser structure.
 * \param    node   Pointer to the current parse tree node.
 * \param    cookie Pointer to the help stack.
 *
 * \return   Return CPARSER_OK always.
 */
static cparser_result_t
cparser_help_post_walker (cparser_t *parser, cparser_node_t *node, void *cookie)
{
    help_stack_t *hs = (help_stack_t *)cookie;
    int n, do_print;

    assert(parser && node && hs);
    if ((CPARSER_NODE_END == node->type) &&
        (!(node->flags & CPARSER_NODE_FLAGS_OPT_PARTIAL))) {
        do_print = 0;
        if (hs->filter) {
            /* We have a filter string. Check if it matches any keyword */
            for (n = 0; n < hs->tos; n++) {
                if (CPARSER_NODE_LIST == hs->nodes[n]->type) {
                    /* LIST node requires an extra walk of all keywords in the list */
                    cparser_list_node_t *lnode =
                        (cparser_list_node_t *)hs->nodes[n]->param;
                    assert(lnode);
                    while (lnode) {
                        if (strstr(lnode->keyword, hs->filter)) {
                            do_print = 1;
                            break;
                        }
                        lnode = lnode->next;
                    }
                    if (do_print) {
                        break;
                    }
                }
                if (CPARSER_NODE_KEYWORD != hs->nodes[n]->type) {
                    continue;
                }
                if (strstr(hs->nodes[n]->param, hs->filter)) {
                    do_print = 1; /* Yes, print it */
                    break;
                }
            }
            if (!NODE_USABLE(parser, node)) {
                do_print = 0; /* may match the filter but not usable */
            }
        } else if (NODE_USABLE(parser, node)) {
            do_print = 1;
        }
        if (do_print) {
            cparser_node_t *cur_node;
            int m, num_braces = 0;

            if (node->desc) {
                parser->cfg.prints(parser, node->desc);
                parser->cfg.prints(parser, "\r\n  ");
            } else {
                parser->cfg.prints(parser, "\r  ");
            }
            for (n = 0; n < hs->tos; n++) {
                cur_node = hs->nodes[n];
                if ((CPARSER_NODE_ROOT == cur_node->type) ||
                    (CPARSER_NODE_END == cur_node->type)) {
                    continue;
                }
                if (cur_node->flags & CPARSER_NODE_FLAGS_OPT_START) {
                    parser->cfg.prints(parser, "{ ");
                    num_braces++;
                }
                cparser_help_print_node(parser, cur_node, 0, 0);
                parser->cfg.printc(parser, ' ');
                if (cur_node->flags & CPARSER_NODE_FLAGS_OPT_END) {
                    for (m = 0; m < num_braces; m++) {
                        parser->cfg.prints(parser, "} ");
                    }
                }
            }
            parser->cfg.prints(parser, "\r\n\n");
        }
    }

    /* Pop the stack */
    hs->tos--;
    return CPARSER_OK;
}

cparser_result_t
cparser_help_cmd (cparser_t *parser, char *str)
{
    help_stack_t help_stack;

    assert(parser);
    memset(&help_stack, 0, sizeof(help_stack));
    help_stack.filter = str;
    return cparser_walk(parser, cparser_help_pre_walker,
                        cparser_help_post_walker, &help_stack);
}

cparser_result_t
cparser_set_root_context (cparser_t *parser, void *context)
{
    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    parser->context.cookie[0] = context;
    return CPARSER_OK;
}

cparser_result_t
cparser_get_root_context (cparser_t *parser, void **context)
{
    if (!parser || !context) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    *context = parser->context.cookie[0];
    return CPARSER_OK;
}

cparser_result_t
cparser_set_privileged_mode (cparser_t *parser, int enable)
{
    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    parser->is_privileged_mode = (0 != enable);
    return CPARSER_OK;
}

int
cparser_is_in_privileged_mode (const cparser_t *parser)
{
    if (!parser) {
        return 0;
    }
    return (parser->is_privileged_mode ? 1 : 0);
}

cparser_result_t
cparser_user_input (cparser_t *parser, const char *prompt, int do_echo,
                    char *buf, int buf_size, cparser_input_cb cb)
{
    int tmp_do_echo;

    if (!parser || !buf || !buf_size || !buf_size) {
        return CPARSER_ERR_INVALID_PARAMS;
    }

    if (cparser_is_user_input(parser, &tmp_do_echo)) {
        return CPARSER_NOT_OK; /* only one user input at a time */
    }

    /* Print the prompt */
    if (prompt) {
        parser->cfg.prints(parser, prompt);
    }

    /* Save the state */
    parser->user_buf = buf;
    parser->user_buf_size = buf_size;
    parser->user_input_cb = cb;
    parser->user_do_echo = do_echo;
    assert(!parser->user_buf_count);

    return CPARSER_OK;
}

cparser_result_t
cparser_abort_user_input (cparser_t *parser)
{
    int do_echo;

    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    if (!cparser_is_user_input(parser, &do_echo)) {
        return CPARSER_ERR_NOT_EXIST;
    }

    /* Force a callback immediately with an empty input */
    parser->user_buf[0] = '\0';
    parser->user_input_cb(parser, parser->user_buf, 0);

    cparser_input_reset(parser);
    cparser_print_prompt(parser);

    return CPARSER_OK;
}

cparser_result_t
cparser_last_command (cparser_t *parser, char **cmd,
                      cparser_result_t *rc, int *is_priv)
{
    if (!parser) {
        return CPARSER_ERR_INVALID_PARAMS;
    }
    if (0 <= parser->last_line_idx) {
        if (cmd) {
            *cmd = parser->lines[parser->last_line_idx].buf;
        }
        if (rc) {
            *rc = parser->last_rc;
        }
        if (is_priv) {
            *is_priv = (!parser->last_end_node ? 0 :
                        (parser->last_end_node->flags &
                         CPARSER_NODE_FLAGS_HIDDEN ? 1 : 0));
        }
    } else {
        assert((CPARSER_ERR_NOT_EXIST == parser->last_rc) &&
               (!parser->last_end_node));
        if (cmd) {
            *cmd = NULL;
        }
        if (rc) {
            *rc = parser->last_rc;
        }
        if (is_priv) {
            *is_priv = 0;
        }
    }
    return CPARSER_OK;
}
