/*
Copyright (c) 2014 Vyronas Tsingaras (vtsingaras@it.auth.gr)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


#ifndef ext_auth_LISTENER_H_
#define ext_auth_LISTENER_H_

#include <bus/listeners/listener.h>

typedef struct ext_auth_listener_t ext_auth_listener_t;

/**
 * Listener checking connecting peer against a whitelist.
 */
struct ext_auth_listener_t {

	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Enable/Disable ext_auth.
	 *
	 * @param enable	TRUE to enable, FALSE to disable
	 */
	void (*set_active)(ext_auth_listener_t *this, bool enable);

	/**
	 * Set path to authorization script.
	 *
	 * @param path		full path to script
	 */
	void (*set_path)(ext_auth_listener_t *this, char* path);
};

/**
 * Create a ext_auth_listener instance.
 */
ext_auth_listener_t *ext_auth_listener_create(char* program_path);

#endif /** ext_auth_LISTENER_H_ @}*/
