/* tncifimc.h
 *
 * Trusted Network Connect IF-IMC API version 1.20 Revision 8
 * Microsoft Windows DLL Platform Binding C Header
 * February 5, 2007
 *
 * Copyright(c) 2005-2007, Trusted Computing Group, Inc. All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * - Neither the name of the Trusted Computing Group nor the names of
 *   its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact the Trusted Computing Group at
 * admin@trustedcomputinggroup.org for information on specification
 * licensing through membership agreements.
 *
 * Any marks and brands contained herein are the property of their
 * respective owners.
 *
 */

/**
 * @defgroup tncifimc tncifimc
 * @{ @ingroup tnc
 */

#ifndef TNCIFIMC_H_
#define TNCIFIMC_H_

#include "tncif.h"

/* Derived Types */

typedef TNC_UInt32 TNC_IMCID;

/* Function pointers */

typedef TNC_Result (*TNC_IMC_InitializePointer)(
    TNC_IMCID imcID,
    TNC_Version minVersion,
    TNC_Version maxVersion,
    TNC_Version *pOutActualVersion);
typedef TNC_Result (*TNC_IMC_NotifyConnectionChangePointer)(
    TNC_IMCID imcID,
    TNC_ConnectionID connectionID,
    TNC_ConnectionState newState);
typedef TNC_Result (*TNC_IMC_BeginHandshakePointer)(
    TNC_IMCID imcID,
    TNC_ConnectionID connectionID);
typedef TNC_Result (*TNC_IMC_ReceiveMessagePointer)(
    TNC_IMCID imcID,
    TNC_ConnectionID connectionID,
    TNC_BufferReference message,
    TNC_UInt32 messageLength,
    TNC_MessageType messageType);
typedef TNC_Result (*TNC_IMC_BatchEndingPointer)(
    TNC_IMCID imcID,
    TNC_ConnectionID connectionID);
typedef TNC_Result (*TNC_IMC_TerminatePointer)(
    TNC_IMCID imcID);
typedef TNC_Result (*TNC_TNCC_ReportMessageTypesPointer)(
    TNC_IMCID imcID,
    TNC_MessageTypeList supportedTypes,
    TNC_UInt32 typeCount);
typedef TNC_Result (*TNC_TNCC_SendMessagePointer)(
    TNC_IMCID imcID,
    TNC_ConnectionID connectionID,
    TNC_BufferReference message,
    TNC_UInt32 messageLength,
    TNC_MessageType messageType);
typedef TNC_Result (*TNC_TNCC_RequestHandshakeRetryPointer)(
    TNC_IMCID imcID,
    TNC_ConnectionID connectionID,
    TNC_RetryReason reason);
typedef TNC_Result (*TNC_TNCC_BindFunctionPointer)(
    TNC_IMCID imcID,
    char *functionName,
    void **pOutfunctionPointer);
typedef TNC_Result (*TNC_IMC_ProvideBindFunctionPointer)(
    TNC_IMCID imcID,
    TNC_TNCC_BindFunctionPointer bindFunction);

#define TNC_IFIMC_VERSION_1 1

/* Handshake Retry Reason Values */

#define TNC_RETRY_REASON_IMC_REMEDIATION_COMPLETE 0
#define TNC_RETRY_REASON_IMC_SERIOUS_EVENT 1
#define TNC_RETRY_REASON_IMC_INFORMATIONAL_EVENT 2
#define TNC_RETRY_REASON_IMC_PERIODIC 3
/* reserved for TNC_RETRY_REASON_IMV_IMPORTANT_POLICY_CHANGE: 4 */
/* reserved for TNC_RETRY_REASON_IMV_MINOR_POLICY_CHANGE: 5 */
/* reserved for TNC_RETRY_REASON_IMV_SERIOUS_EVENT: 6 */
/* reserved for TNC_RETRY_REASON_IMV_MINOR_EVENT: 7 */
/* reserved for TNC_RETRY_REASON_IMV_PERIODIC: 8 */

/* IMC Functions */

TNC_Result TNC_IMC_Initialize(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_Version minVersion,
/*in*/  TNC_Version maxVersion,
/*out*/ TNC_Version *pOutActualVersion);

TNC_Result TNC_IMC_NotifyConnectionChange(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_ConnectionState newState);

TNC_Result TNC_IMC_BeginHandshake(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID);

TNC_Result TNC_IMC_ReceiveMessage(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_BufferReference messageBuffer,
/*in*/  TNC_UInt32 messageLength,
/*in*/  TNC_MessageType messageType);

TNC_Result TNC_IMC_BatchEnding(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID);

TNC_Result TNC_IMC_Terminate(
/*in*/  TNC_IMCID imcID);

TNC_Result TNC_IMC_ProvideBindFunction(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_TNCC_BindFunctionPointer bindFunction);

/* TNC Client Functions */

TNC_Result TNC_TNCC_ReportMessageTypes(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_MessageTypeList supportedTypes,
/*in*/  TNC_UInt32 typeCount);

TNC_Result TNC_TNCC_SendMessage(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_BufferReference message,
/*in*/  TNC_UInt32 messageLength,
/*in*/  TNC_MessageType messageType);

TNC_Result TNC_TNCC_RequestHandshakeRetry(
/*in*/  TNC_IMCID imcID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_RetryReason reason);

TNC_Result TNC_TNCC_BindFunction(
/*in*/  TNC_IMCID imcID,
/*in*/  char *functionName,
/*out*/ void **pOutfunctionPointer);

#endif /** TNCIFIMC_H_ @}*/
