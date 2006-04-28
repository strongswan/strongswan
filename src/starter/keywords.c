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
 * RCSID $Id: keywords.c,v 1.7 2006/04/17 10:32:48 as Exp $
 */

#include <string.h>

#include "keywords.h"

struct kw_entry {
    char *name;
    kw_token_t token;
};

#define TOTAL_KEYWORDS 77
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 9
#define MAX_HASH_VALUE 146
/* maximum key range = 138, duplicates = 0 */

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
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
       15, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147,  85, 147,  40,
       25,  25,   0,  10,   5,  80, 147,  35,  60,  35,
       60,  55,  10, 147,  15,  20,   5,  65, 147, 147,
      147,  35,   0, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147, 147, 147, 147, 147,
      147, 147, 147, 147, 147, 147
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
    {"rekeyfuzz",         KW_REKEYFUZZ},
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
    {"auto",              KW_AUTO},
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
    {"keyingtries",       KW_KEYINGTRIES},
    {"keylife",           KW_KEYLIFE},
    {"dpddelay",          KW_DPDDELAY},
    {"cachecrls",         KW_CACHECRLS},
    {"leftupdown",        KW_LEFTUPDOWN},
    {"keyexchange",       KW_KEYEXCHANGE},
    {"leftfirewall",      KW_LEFTFIREWALL},
    {"nocrsend",          KW_NOCRSEND},
    {""},
    {"rekey",             KW_REKEY},
    {"leftsubnetwithin",  KW_LEFTSUBNETWITHIN},
    {"pkcs11module",      KW_PKCS11MODULE},
    {"nat_traversal",     KW_NAT_TRAVERSAL},
    {"also",              KW_ALSO},
    {"pkcs11keepstate",   KW_PKCS11KEEPSTATE},
    {"rightupdown",       KW_RIGHTUPDOWN},
    {"crluri2",           KW_CRLURI2},
    {"rightfirewall",     KW_RIGHTFIREWALL},
    {"postpluto",         KW_POSTPLUTO},
    {"plutodebug",        KW_PLUTODEBUG},
    {"pkcs11proxy",       KW_PKCS11PROXY},
    {"rightsubnetwithin", KW_RIGHTSUBNETWITHIN},
    {"prepluto",          KW_PREPLUTO},
    {""}, {""},
    {"leftca",            KW_LEFTCA},
    {""}, {""},
    {"dpdaction",         KW_DPDACTION},
    {""}, {""}, {""},
    {"ldaphost",          KW_LDAPHOST},
    {""},
    {"klipsdebug",        KW_KLIPSDEBUG},
    {"overridemtu",       KW_OVERRIDEMTU},
    {"rightca",           KW_RIGHTCA},
    {"fragicmp",          KW_FRAGICMP},
    {""}, {""},
    {"rekeymargin",       KW_REKEYMARGIN},
    {"ocspuri",           KW_OCSPURI},
    {""},
    {"uniqueids",         KW_UNIQUEIDS},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {"ldapbase",          KW_LDAPBASE},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {"crlcheckinterval",  KW_CRLCHECKINTERVAL},
    {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""}, {""},
    {"crluri",            KW_CRLURI}
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
