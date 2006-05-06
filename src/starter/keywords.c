/* C code produced by gperf version 3.0.1 */
/* Command-line: gperf -C -G -t  */
/* Computed positions: -k'3,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif


/* strongSwan keywords
 * Copyright (C) 2005 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: keywords.txt,v 1.6 2006/04/17 10:30:27 as Exp $
 */

#include <string.h>

#include "keywords.h"

struct kw_entry {
    char *name;
    kw_token_t token;
};

#define TOTAL_KEYWORDS 79
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 9
#define MAX_HASH_VALUE 156
/* maximum key range = 148, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned char asso_values[] =
    {
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
       20, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157,  75, 157,  40,
       25,  25,   0,  10,   5,  55, 157,  65,  60,  35,
       80,  65,  10, 157,  15,  20,   5,  80, 157, 157,
      157,  35,   5, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157, 157, 157, 157, 157,
      157, 157, 157, 157, 157, 157
    };
  return len + asso_values[(unsigned char)str[2]] + asso_values[(unsigned char)str[len - 1]];
}

static const struct kw_entry wordlist[] =
  {
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {"left",              KW_LEFT},
    {""}, {""}, {""},
    {"leftcert",          KW_LEFTCERT,},
    {"auth",              KW_AUTH},
    {"leftsubnet",        KW_LEFTSUBNET},
    {""},
    {"leftsendcert",      KW_LEFTSENDCERT},
    {"leftprotoport",     KW_LEFTPROTOPORT},
    {""},
    {"right",             KW_RIGHT},
    {"leftnexthop",       KW_LEFTNEXTHOP},
    {"leftsourceip",      KW_LEFTSOURCEIP},
    {"esp",               KW_ESP},
    {"rightcert",         KW_RIGHTCERT},
    {""},
    {"rightsubnet",       KW_RIGHTSUBNET},
    {""},
    {"rightsendcert",     KW_RIGHTSENDCERT},
    {"rightprotoport",    KW_RIGHTPROTOPORT},
    {"leftgroups",        KW_LEFTGROUPS},
    {"leftid",            KW_LEFTID},
    {"rightnexthop",      KW_RIGHTNEXTHOP},
    {"rightsourceip",     KW_RIGHTSOURCEIP},
    {"lefthostaccess",    KW_LEFTHOSTACCESS},
    {"interfaces",        KW_INTERFACES},
    {""}, {""},
    {"pfsgroup",          KW_PFSGROUP},
    {"type",              KW_TYPE},
    {"dpdtimeout",        KW_DPDTIMEOUT},
    {"rightgroups",       KW_RIGHTGROUPS},
    {"rightid",           KW_RIGHTID},
    {"pfs",               KW_PFS},
    {""},
    {"righthostaccess",   KW_RIGHTHOSTACCESS},
    {"authby",            KW_AUTHBY},
    {""},
    {"leftrsasigkey",     KW_LEFTRSASIGKEY},
    {""}, {""},
    {"cacert",            KW_CACERT},
    {"hidetos",           KW_HIDETOS},
    {"ike",               KW_IKE},
    {""},
    {"virtual_private",   KW_VIRTUAL_PRIVATE},
    {""},
    {"dumpdir",           KW_DUMPDIR},
    {"packetdefault",     KW_PACKETDEFAULT},
    {"rightrsasigkey",    KW_RIGHTRSASIGKEY},
    {"keep_alive",        KW_KEEP_ALIVE},
    {"ikelifetime",       KW_IKELIFETIME},
    {""},
    {"compress",          KW_COMPRESS},
    {""},
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
    {"keyingtries",       KW_KEYINGTRIES},
    {"keylife",           KW_KEYLIFE},
    {"dpddelay",          KW_DPDDELAY},
    {"cachecrls",         KW_CACHECRLS},
    {""},
    {"keyexchange",       KW_KEYEXCHANGE},
    {"leftfirewall",      KW_LEFTFIREWALL},
    {"nocrsend",          KW_NOCRSEND},
    {"auto",              KW_AUTO},
    {"klipsdebug",        KW_KLIPSDEBUG},
    {""},
    {"pkcs11module",      KW_PKCS11MODULE},
    {"nat_traversal",     KW_NAT_TRAVERSAL},
    {"rekeyfuzz",         KW_REKEYFUZZ},
    {"pkcs11keepstate",   KW_PKCS11KEEPSTATE},
    {"leftca",            KW_LEFTCA},
    {"ocspuri",           KW_OCSPURI},
    {"rightfirewall",     KW_RIGHTFIREWALL},
    {"uniqueids",         KW_UNIQUEIDS},
    {""},
    {"pkcs11proxy",       KW_PKCS11PROXY},
    {"crluri2",           KW_CRLURI2},
    {"ldaphost",          KW_LDAPHOST},
    {"also",              KW_ALSO},
    {"leftupdown",        KW_LEFTUPDOWN},
    {"charonstart",       KW_CHARONSTART},
    {"rightca",           KW_RIGHTCA},
    {"fragicmp",          KW_FRAGICMP},
    {"postpluto",         KW_POSTPLUTO},
    {"plutostart",        KW_PLUTOSTART},
    {"leftsubnetwithin",  KW_LEFTSUBNETWITHIN},
    {""},
    {"prepluto",          KW_PREPLUTO},
    {""},
    {"plutodebug",        KW_PLUTODEBUG},
    {"rightupdown",       KW_RIGHTUPDOWN},
    {""}, {""}, {""},
    {"rekey",             KW_REKEY},
    {""},
    {"rightsubnetwithin", KW_RIGHTSUBNETWITHIN},
    {"ldapbase",          KW_LDAPBASE},
    {""}, {""}, {""}, {""}, {""},
    {"dpdaction",         KW_DPDACTION},
    {""},
    {"overridemtu",       KW_OVERRIDEMTU},
    {""}, {""}, {""}, {""},
    {"crluri",            KW_CRLURI},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""},
    {"crlcheckinterval",  KW_CRLCHECKINTERVAL},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""},
    {"rekeymargin",       KW_REKEYMARGIN}
  };

#ifdef __GNUC__
__inline
#endif
const struct kw_entry *
in_word_set (str, len)
     register const char *str;
     register unsigned int len;
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].name;

          if (*str == *s && !strcmp (str + 1, s + 1))
            return &wordlist[key];
        }
    }
  return 0;
}
