/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (C) 2001, 2002, 2004, 2007, 2008, 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "crypto_int.h"

krb5_error_code KRB5_CALLCONV
krb5_c_random_seed(krb5_context context, krb5_data *data)
{
    return krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OLDAPI, data);
}

/* Routines to get entropy from the OS. */
#if defined(_WIN32)

krb5_boolean
k5_get_os_entropy(unsigned char *buf, size_t len)
{
    krb5_boolean result;
    HCRYPTPROV provider;

    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT))
    {
        HRESULT result = GetLastError();
        const char *msg = "Unknown Error";
        switch (result)
        {
        case ERROR_BUSY: /* 107L  */
            msg = "Some CSPs set this error if the CRYPT_DELETEKEYSET flag value is set and another thread or process is using this key container.";
            break;

        case ERROR_FILE_NOT_FOUND: /* 2L */
            msg = "The profile of the user is not loaded and cannot be found. This happens when the application impersonates a user, for example, the IUSR_ComputerName account.";
            break;

        case ERROR_INVALID_PARAMETER: /* 87L */
            msg = "One of the parameters contains a value that is not valid. This is most often a pointer that is not valid.";
            break;

        case ERROR_NOT_ENOUGH_MEMORY: /* 8L */
            msg = "The operating system ran out of memory during the operation.";
            break;

        case NTE_BAD_FLAGS: /* 0x80090009L */
            msg = "The dwFlags parameter has a value that is not valid.";
            break;

        case NTE_BAD_KEY_STATE: /* 0x8009000BL */
            msg = "The user password has changed since the private keys were encrypted.";
            break;

        case NTE_BAD_KEYSET: /* 0x80090016L */
            msg = "The key container could not be opened. A common cause of this error is that the key container does not exist. To create a key container, call CryptAcquireContext using the CRYPT_NEWKEYSET flag. This error code can also indicate that access to an existing key container is denied. Access rights to the container can be granted by the key set creator by using CryptSetProvParam.";
            break;

        case NTE_BAD_KEYSET_PARAM: /* 0x8009001FL */
            msg = "The pszContainer or pszProvider parameter is set to a value that is not valid.";
            break;

        case NTE_BAD_PROV_TYPE: /* 0x80090014L */
            msg = "The value of the dwProvType parameter is out of range. All provider types must be from 1 through 999, inclusive.";
            break;

        case NTE_BAD_SIGNATURE: /* 0x80090006L */
            msg = "The provider DLL signature could not be verified. Either the DLL or the digital signature has been tampered with.";
            break;

        case NTE_EXISTS: /* 0x8009000FL */
            msg = "The dwFlags parameter is CRYPT_NEWKEYSET, but the key container already exists.";
            break;

        case NTE_KEYSET_ENTRY_BAD: /* 0x8009001AL */
            msg = "The pszContainer key container was found but is corrupt.";
            break;

        case NTE_KEYSET_NOT_DEF: /* 0x80090019L */
            msg = "The requested provider does not exist.";
            break;

        case NTE_NO_MEMORY: /* 0x8009000EL */
            msg = "The CSP ran out of memory during the operation.";
            break;

        case NTE_PROV_DLL_NOT_FOUND: /* 0x8009001EL */
            msg = "The provider DLL file does not exist or is not on the current path.";
            break;

        case NTE_PROV_TYPE_ENTRY_BAD: /* 0x80090018L */
            msg = "The provider type specified by dwProvType is corrupt. This error can relate to either the user default CSP list or the computer default CSP list.";
            break;

        case NTE_PROV_TYPE_NO_MATCH: /* 0x8009001BL */
            msg = "The provider type specified by dwProvType does not match the provider type found. Note that this error can only occur when pszProvider specifies an actual CSP name.";
            break;

        case NTE_PROV_TYPE_NOT_DEF: /* 0x80090017L */
            msg = "No entry exists for the provider type specified by dwProvType.";
            break;

        case NTE_PROVIDER_DLL_FAIL: /* 0x8009001DL */
            msg = "The provider DLL file could not be loaded or failed to initialize.";
            break;

        case NTE_SIGNATURE_FILE_BAD: /* 0x8009001CL */
            msg = "An error occurred while loading the DLL file image, prior to verifying its signature.";
            break;

        default:
            break;
        }
        return FALSE;
    }
    result = CryptGenRandom(provider, len, buf);
    (void)CryptReleaseContext(provider, 0);
    return result;
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    int oursuccess = 0;
    char buf[1024];
    krb5_data data = make_data(buf, sizeof(buf));

    if (k5_get_os_entropy(buf, sizeof(buf)) &&
        krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OSRAND,
                                  &data) == 0)
        oursuccess = 1;
    if (success != NULL)
        *success = oursuccess;
    return 0;
}

#else /* not Windows */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

/* Open device, ensure that it is not a regular file, and read entropy.  Return
 * true on success, false on failure. */
static krb5_boolean
read_entropy_from_device(const char *device, unsigned char *buf, size_t len)
{
    struct stat sb;
    int fd;
    unsigned char *bp;
    size_t left;
    ssize_t count;
    krb5_boolean result = FALSE;

    fd = open(device, O_RDONLY);
    if (fd == -1)
        return FALSE;
    set_cloexec_fd(fd);
    if (fstat(fd, &sb) == -1 || S_ISREG(sb.st_mode))
        goto cleanup;

    for (bp = buf, left = len; left > 0;) {
        count = read(fd, bp, left);
        if (count <= 0)
            goto cleanup;
        left -= count;
        bp += count;
    }
    result = TRUE;

cleanup:
    close(fd);
    return result;
}

krb5_boolean
k5_get_os_entropy(unsigned char *buf, size_t len)
{
    return read_entropy_from_device("/dev/urandom", buf, len);
}

/* Read entropy from device and contribute it to the PRNG.  Returns true on
 * success. */
static krb5_boolean
add_entropy_from_device(krb5_context context, const char *device)
{
    krb5_data data;
    unsigned char buf[64];

    if (!read_entropy_from_device(device, buf, sizeof(buf)))
        return FALSE;
    data = make_data(buf, sizeof(buf));
    return (krb5_c_random_add_entropy(context, KRB5_C_RANDSOURCE_OSRAND,
                                      &data) == 0);
}

krb5_error_code KRB5_CALLCONV
krb5_c_random_os_entropy(krb5_context context, int strong, int *success)
{
    int unused;
    int *oursuccess = (success != NULL) ? success : &unused;

    *oursuccess = 0;
    /* If we are getting strong data then try that first.  We are
       guaranteed to cause a reseed of some kind if strong is true and
       we have both /dev/random and /dev/urandom.  We want the strong
       data included in the reseed so we get it first.*/
    if (strong) {
        if (add_entropy_from_device(context, "/dev/random"))
            *oursuccess = 1;
    }
    if (add_entropy_from_device(context, "/dev/urandom"))
        *oursuccess = 1;
    return 0;
}

#endif /* not Windows */
