/* Copyright (C) 2019-2020 Marvell */

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

