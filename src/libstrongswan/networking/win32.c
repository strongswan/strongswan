/*
 * Copyright (C) 2016 Noel Kuntze
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
 * This file contains helper functions for the handling of TAP devices on Windows.
 * This code is largely copied from the openvpn source code with parts modified
 * or removed.
 */
#ifdef WIN32

#include <tap-windows.h>
#include <winioctl.h>
#include "win32.h"

/* Find the guid of the given device in the registry */

/*
 * Get an adapter GUID from the
 * registry for the TAP device # = device_number.
 */
static const char *
get_unspecified_device_guid(const int device_number,
        const struct tap_reg *tap_reg_src,
        const struct panel_reg *panel_reg_src)
{
    const struct tap_reg *tap_reg = tap_reg_src;
    struct buffer ret = clear_buf();
    struct buffer actual = clear_buf();
    int i;

    ASSERT(device_number >= 0);

    /* Make sure we have at least one TAP adapter */
    if (!tap_reg)
        return NULL;

    /* Move on to specified device number */
    for (i = 0; i < device_number; i++)
    {
        tap_reg = tap_reg->next;
        if (!tap_reg)
            return NULL;
    }

    /* TODO: Rewrite */

    /* Save GUID for return value */
    /* TODO: Rewrite */
    linked_list_t list = linked_list_create();
    ret = alloc_buf_gc(256, gc);
    buf_printf(&ret, "%s", tap_reg->guid);
    return BSTR(&ret);
}

/*
 * Lookup a --dev-node adapter name in the registry
 * returning the GUID and optional actual_name.
 * TODO: Rewrite
 */
static const char *
get_device_guid(const char *name,
        char *actual_name,
        int actual_name_size,
        const struct tap_reg *tap_reg,
        const struct panel_reg *panel_reg,)
{
    struct buffer ret = alloc_buf_gc(256, gc);
    struct buffer actual = clear_buf();

    /* Make sure we have at least one TAP adapter */
    if (!tap_reg)
        return NULL;

    /* The actual_name output buffer may be NULL */
    if (actual_name)
    {
        ASSERT(actual_name_size > 0);
        buf_set_write(&actual, actual_name, actual_name_size);
    }

    /* Check if GUID was explicitly specified as --dev-node parameter */
    if (is_tap_win(name, tap_reg))
    {
        const char *act = guid_to_name(name, panel_reg);
        buf_printf(&ret, "%s", name);
        if (act)
            buf_printf(&actual, "%s", act);
        else
            buf_printf(&actual, "%s", name);
        return BSTR(&ret);
    }

    /* Lookup TAP adapter in network connections list */
    {
        const char *guid = name_to_guid(name, tap_reg, panel_reg);
        if (guid)
        {
            buf_printf(&actual, "%s", name);
            buf_printf(&ret, "%s", guid);
            return BSTR(&ret);
        }
    }

    return NULL;
}

/*
 * Translates a GUID to a name
 * TODO: Rewrite
 */
static const char *
guid_to_name(const char *guid, const struct panel_reg *panel_reg)
{
    const struct panel_reg *pr;

    for (pr = panel_reg; pr != NULL; pr = pr->next)
    {
        if (guid && !strcmp(pr->guid, guid))
            return pr->name;
    }

    return NULL;
}

#endif