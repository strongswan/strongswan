/*
 * Copyright (C) 2019-2020 Marvell 
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

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   auth_els_utils.h
 * Author: cwinkler
 *
 * Created on February 19, 2020, 8:02 AM
 */

#include <pthread.h>

#ifndef AUTH_ELS_UTILS_H
#define AUTH_ELS_UTILS_H

#define DBG_ENTER { \
    char final_format[1024]; \
    sprintf (final_format, "%s: %s: %d: enter, thread_id: %lx", __FILE__, __func__, __LINE__, pthread_self()); \
    DBG1 (DBG_CFG, final_format); \
}

#define DBG_STD(format, ...) { \
    char final_format[1024]; \
    sprintf (final_format, "%s: %s: %d: %s, thread_id: %lx", __FILE__, __func__, __LINE__, format, pthread_self()); \
    DBG1 (DBG_CFG, final_format, ##__VA_ARGS__); \
}

#define DBG_FATAL(format, ...) { \
    char final_format[1024]; \
    sprintf (final_format, "%s: %s: %d: FATAL_ERROR: %s, thread_id: %lx", __FILE__, __func__, __LINE__, format, pthread_self()); \
    DBG0 (DBG_CFG, final_format, ##__VA_ARGS__); \
}

#endif /* AUTH_ELS_UTILS_H */

