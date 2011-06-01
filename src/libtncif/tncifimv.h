/* tncifimv.h
 *
 * Trusted Network Connect IF-IMV API version 1.20
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
 */

/**
 * @defgroup tncifimv tncifimv
 * @{ @ingroup tnc
 */

#ifndef TNCIFIMV_H_
#define TNCIFIMV_H_

#include "tncif.h"

#include <library.h>

typedef TNC_UInt32 TNC_IMVID;
typedef TNC_UInt32 TNC_IMV_Action_Recommendation;
typedef TNC_UInt32 TNC_IMV_Evaluation_Result;
typedef TNC_UInt32 TNC_AttributeID;

/* Function pointers */

typedef TNC_Result (*TNC_IMV_InitializePointer)(
	TNC_IMVID imvID,
	TNC_Version minVersion,
	TNC_Version maxVersion,
	TNC_Version *pOutActualVersion);
typedef TNC_Result (*TNC_IMV_NotifyConnectionChangePointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID,
	TNC_ConnectionState newState);
typedef TNC_Result (*TNC_IMV_ReceiveMessagePointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID,
	TNC_BufferReference message,
	TNC_UInt32 messageLength,
	TNC_MessageType messageType);
typedef TNC_Result (*TNC_IMV_SolicitRecommendationPointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID);
typedef TNC_Result (*TNC_IMV_BatchEndingPointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID);
typedef TNC_Result (*TNC_IMV_TerminatePointer)(
	TNC_IMVID imvID);
typedef TNC_Result (*TNC_TNCS_ReportMessageTypesPointer)(
	TNC_IMVID imvID,
	TNC_MessageTypeList supportedTypes,
	TNC_UInt32 typeCount);
typedef TNC_Result (*TNC_TNCS_SendMessagePointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID,
	TNC_BufferReference message,
	TNC_UInt32 messageLength,
	TNC_MessageType messageType);
typedef TNC_Result (*TNC_TNCS_RequestHandshakeRetryPointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID,
	TNC_RetryReason reason);
typedef TNC_Result (*TNC_TNCS_ProvideRecommendationPointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID,
	TNC_IMV_Action_Recommendation recommendation,
	TNC_IMV_Evaluation_Result evaluation);
typedef TNC_Result (*TNC_TNCS_GetAttributePointer)(
	TNC_IMVID imvID,
TNC_ConnectionID connectionID,
TNC_AttributeID attributeID,
	TNC_UInt32 bufferLength,
	TNC_BufferReference buffer,
	TNC_UInt32 *pOutValueLength);
typedef TNC_Result (*TNC_TNCS_SetAttributePointer)(
	TNC_IMVID imvID,
	TNC_ConnectionID connectionID,
TNC_AttributeID attributeID,
	TNC_UInt32 bufferLength,
	TNC_BufferReference buffer);
typedef TNC_Result (*TNC_TNCS_BindFunctionPointer)(
	TNC_IMVID imvID,
	char *functionName,
	void **pOutfunctionPointer);
typedef TNC_Result (*TNC_IMV_ProvideBindFunctionPointer)(
	TNC_IMVID imvID,
	TNC_TNCS_BindFunctionPointer bindFunction);

/* Version Numbers */

#define TNC_IFIMV_VERSION_1 1

/* Handshake Retry Reason Values */

/* reserved for TNC_RETRY_REASON_IMC_REMEDIATION_COMPLETE: 0 */
/* reserved for TNC_RETRY_REASON_IMC_SERIOUS_EVENT: 1 */
/* reserved for TNC_RETRY_REASON_IMC_INFORMATIONAL_EVENT: 2 */
/* reserved for TNC_RETRY_REASON_IMC_PERIODIC: 3 */
#define TNC_RETRY_REASON_IMV_IMPORTANT_POLICY_CHANGE 4
#define TNC_RETRY_REASON_IMV_MINOR_POLICY_CHANGE 5
#define TNC_RETRY_REASON_IMV_SERIOUS_EVENT 6
#define TNC_RETRY_REASON_IMV_MINOR_EVENT 7
#define TNC_RETRY_REASON_IMV_PERIODIC 8

/* IMV Action Recommendation Values */

#define TNC_IMV_ACTION_RECOMMENDATION_ALLOW 0
#define TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS 1
#define TNC_IMV_ACTION_RECOMMENDATION_ISOLATE 2
#define TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION 3

extern enum_name_t *TNC_IMV_Action_Recommendation_names;

/* IMV Evaluation Result Values */

#define TNC_IMV_EVALUATION_RESULT_COMPLIANT 0
#define TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR 1
#define TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR 2
#define TNC_IMV_EVALUATION_RESULT_ERROR 3
#define TNC_IMV_EVALUATION_RESULT_DONT_KNOW 4

extern enum_name_t *TNC_IMV_Evaluation_Result_names;

/* Message Attribute ID Values */

#define TNC_ATTRIBUTEID_PREFERRED_LANGUAGE ((TNC_AttributeID) 0x00000001)
#define TNC_ATTRIBUTEID_REASON_STRING ((TNC_AttributeID) 0x00000002)
#define TNC_ATTRIBUTEID_REASON_LANGUAGE ((TNC_AttributeID) 0x00000003)

/* IMV Functions */

TNC_Result TNC_IMV_Initialize(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_Version minVersion,
/*in*/  TNC_Version maxVersion,
/*in*/  TNC_Version *pOutActualVersion);

TNC_Result TNC_IMV_NotifyConnectionChange(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_ConnectionState newState);

TNC_Result TNC_IMV_ReceiveMessage(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_BufferReference messageBuffer,
/*in*/  TNC_UInt32 messageLength,
/*in*/  TNC_MessageType messageType);

TNC_Result TNC_IMV_SolicitRecommendation(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID);

TNC_Result TNC_IMV_BatchEnding(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID);

TNC_Result TNC_IMV_Terminate(
/*in*/  TNC_IMVID imvID);

TNC_Result TNC_IMV_ProvideBindFunction(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_TNCS_BindFunctionPointer bindFunction);

/* TNC Server Functions */

TNC_Result TNC_TNCS_ReportMessageTypes(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_MessageTypeList supportedTypes,
/*in*/  TNC_UInt32 typeCount);

TNC_Result TNC_TNCS_SendMessage(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_BufferReference message,
/*in*/  TNC_UInt32 messageLength,
/*in*/  TNC_MessageType messageType);

TNC_Result TNC_TNCS_RequestHandshakeRetry(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_RetryReason reason);

TNC_Result TNC_TNCS_ProvideRecommendation(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_IMV_Action_Recommendation recommendation,
/*in*/  TNC_IMV_Evaluation_Result evaluation);

TNC_Result TNC_TNCS_GetAttribute(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_AttributeID attributeID,
/*in*/  TNC_UInt32 bufferLength,
/*out*/ TNC_BufferReference buffer,
/*out*/ TNC_UInt32 *pOutValueLength);

TNC_Result TNC_TNCS_SetAttribute(
/*in*/  TNC_IMVID imvID,
/*in*/  TNC_ConnectionID connectionID,
/*in*/  TNC_AttributeID attributeID,
/*in*/  TNC_UInt32 bufferLength,
/*in*/  TNC_BufferReference buffer);

TNC_Result TNC_TNCS_BindFunction(
/*in*/  TNC_IMVID imvID,
/*in*/  char *functionName,
/*in*/  void **pOutfunctionPointer);

#endif /** TNCIFIMV_H_ @}*/
