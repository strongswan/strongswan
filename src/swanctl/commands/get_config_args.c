/*
 * Copyright (C) 2017 Noel Kuntze
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

 #include "command.h"

#include <errno.h>
#include <unistd.h>

 static int get_configure_arguments(vici_conn_t *conn)
{

	printf("configure arguments: %s\n", lib->get_configure_arguments(lib));

	return 0;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		get_configure_arguments, 'o', "get-config-args", "prints the ./configure arguments",
		{"[--raw|--pretty]"},
		{
			{"help",		'h', 0, "show usage information"},
			{"raw",			'r', 0, "dump raw response message. Doesn't do anything here."},
			{"pretty",		'P', 0, "dump raw response message in pretty print. Doesn't do anything here."},
		}
	});
}

