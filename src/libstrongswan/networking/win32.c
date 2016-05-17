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

/*
 * Searches through the registry for suitable TAP driver interfaces
 * On Windows, the TAP interface metadata is stored and described in the registry.
 * It returns a linked list that contains all found guids. The guids describe the interfaces.
 */

linked_list_t *get_tap_reg()
{
    HKEY adapter_key;
    LONG status;
    DWORD len;
    linked_list_t list = linked_list_create();
    int i = 0;

    /*
     * Open parent key. It contains all other keys that
     * describe any possible interfaces.
     */
    status = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            ADAPTER_KEY,
            0,
            KEY_READ,
            &adapter_key);

    if (status != ERROR_SUCCESS)
    {
        DBG2(M_FATAL, "Error opening registry key: %s", ADAPTER_KEY);
    }

    while (true)
    {
        char enum_name[256];
        char unit_string[256];
        HKEY unit_key;
        char component_id_string[] = "ComponentId";
        char component_id[256];
        char net_cfg_instance_id_string[] = "NetCfgInstanceId";
        char net_cfg_instance_id[256];
        DWORD data_type;

        len = sizeof (enum_name);
        status = RegEnumKeyEx(
                adapter_key,
                i,
                enum_name,
                &len,
                NULL,
                NULL,
                NULL,
                NULL);
        if (status == ERROR_NO_MORE_ITEMS)
        {
            break;
        }
        else if (status != ERROR_SUCCESS)
        {
            DBG2(M_FATAL, "Error enumerating registry subkeys of key: %s",
                    ADAPTER_KEY);
        }

        snprintf(unit_string, sizeof (unit_string), "%s\\%s",
                ADAPTER_KEY, enum_name);

        status = RegOpenKeyEx(
                HKEY_LOCAL_MACHINE,
                unit_string,
                0,
                KEY_READ,
                &unit_key);

        if (status != ERROR_SUCCESS)
        {
            DBG2(D_REGISTRY, "Error opening registry key: %s", unit_string);
        }
        else
        {
            len = sizeof (component_id);
            status = RegQueryValueEx(
                    unit_key,
                    component_id_string,
                    NULL,
                    &data_type,
                    component_id,
                    &len);

            if (status != ERROR_SUCCESS || data_type != REG_SZ)
            {
                DBG2(D_REGISTRY, "Error opening registry key: %s\\%s",
                        unit_string, component_id_string);
            }
            else
            {
                len = sizeof (net_cfg_instance_id);
                status = RegQueryValueEx(
                        unit_key,
                        net_cfg_instance_id_string,
                        NULL,
                        &data_type,
                        net_cfg_instance_id,
                        &len);

                if (status == ERROR_SUCCESS && data_type == REG_SZ)
                {
                    if (!strcmp(component_id, TAP_WIN_COMPONENT_ID))
                    {
                        /* That thing is a valid interface key */
                        /* link into return list */
                        char *guid = malloc_thing(net_cfg_instance_id);
                        memcpy(guid, net_cfg_instance_id, strlen(net_cfg_instance_id));
                        list->insert_last(list, guid);
                    }
                }
            }
            RegCloseKey(unit_key);
        }
        ++i;
    }

    RegCloseKey(adapter_key);
    return list;
}
#endif