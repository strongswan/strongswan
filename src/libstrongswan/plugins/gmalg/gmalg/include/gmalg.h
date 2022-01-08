/*
 * Cryptographic application identifier criterion specification
 * Code URL     : https://github.com/zhangke5959
 * Maintainer   : Zhang Ke <zhangke5959@126.com>
 */

#ifndef _GMALG_H_
#define _GMALG_H_

#define GMALG_SM1_ECB 0x00000101 /*SM1 算法 ECB 加密模式*/
#define GMALG_SM1_CBC 0x00000102 /*SM1 算法 CBC 加密模式*/
#define GMALG_SM1_CFB 0x00000104 /*SM1 算法 CFB 加密模式*/
#define GMALG_SM1_OFB 0x00000108 /*SM1 算法 OFB 加密模式*/
#define GMALG_SM1_MAC 0x00000110 /*SM1 算法 MAC 加密模式*/

#define GMALG_SM4_ECB 0x00000401 /*SM4 算法 ECB 加密模式*/
#define GMALG_SM4_CBC 0x00000402 /*SM4 算法 CBC 加密模式*/
#define GMALG_SM4_CFB 0x00000404 /*SM4 算法 CFB 加密模式*/
#define GMALG_SM4_OFB 0x00000408 /*SM4 算法 OFB 加密模式*/
#define GMALG_SM4_MAC 0x00000410 /*SM4 算法 MAC 加密模式*/

/**< ECC definition groups */
#define ECCref_MAX_BITS		256
#define ECCref_MAX_LEN		((ECCref_MAX_BITS+7) / 8)

/***********公钥数据结构定义**********/
/* 字段名称  数据长度       含义     */
/*************************************/
/*   bits      4        模长         */
/*   x         32       公钥 x 坐标  */
/*   y         32       公钥 y 坐标  */
/*************************************/
typedef struct ECCrefPublicKey_st {
	unsigned int    bits;
	unsigned char   x[ECCref_MAX_LEN];
	unsigned char   y[ECCref_MAX_LEN];
} ECCrefPublicKey;

/***********私钥数据结构定义******/
/* 字段名称  数据长度    含义    */
/*********************************/
/*   bits      4        模长     */
/*   bits      4        模长     */
/*   D         32       私钥     */
/*********************************/
typedef struct ECCrefPrivateKey_st {
	unsigned int    bits;
	unsigned char   K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/***********加密数据结构定义******************************/
/* 字段名称  数据长度            含义                    */
/*********************************************************/
/*   x         32       与 y 组成椭圆曲线上的点（x，y）  */
/*   y         32       与 x 组成椭圆曲线上的点（x，y）  */
/*   M         32       预留，用于支持带MAC输出的ECC算法 */
/*   L         4        加密数据长度                     */
/*   C         32       加密数据                         */
/*********************************************************/
typedef struct ECCCipher_st {
	unsigned char   x[ECCref_MAX_LEN];
	unsigned char   y[ECCref_MAX_LEN];
	unsigned char   M[ECCref_MAX_LEN];
	unsigned int    L;
	unsigned char   C[ECCref_MAX_LEN];
} ECCCipher;

/***********签名数据结构定义************/
/* 字段名称  数据长度        含义      */
/***************************************/
/*   r         32       签名的 r 部分  */
/*   s         32       签名的 s 部分  */
/***************************************/
typedef struct ECCSignature_st {
	unsigned char   r[ECCref_MAX_LEN];
	unsigned char   s[ECCref_MAX_LEN];
} ECCSignature;

/*
 * 描述： 库测试函数
 * 参数： 无参数
 * 返回值： 0 成功
 *          非 0 失败，返回错误代码
 */
extern int GMALG_LibTest (void);

/*
 * 描述： 打开密码设备
 * 参数： phDeviceHandle[out] 返回设备句柄
 * 返回值： 0 成功
 *          非 0 失败，返回错误代码
 * 备注： phDeviceHandle 由函数初始化并填写内容
 */
extern int GMALG_OpenDevice (void **phDeviceHandle);

/*
 *描述： 关闭密码设备，并释放相关资源
 *参数： hDeviceHandle[in] 已打开的设备句柄
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_CloseDevice (void *hDeviceHandle);

/*
 *描述： 获取指定长度的随机数
 *参数： hDeviceHandle[in]  与设备建立的会话句柄
 *       uiLength[in]       欲获取的随机数长度
 *       pucRandom[out]     缓冲区指针，用于存放获取的随机数
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_GenerateRandom (
	void *hDeviceHandle,
	unsigned int uiLength,
	unsigned char *pucRandom);

/*
 *描述： 请求密码设备 ECC 倍点运算
 *参数： hDeviceHandle[in]  与设备建立的会话句柄
 *       pucG[in]           ECC 基点
 *       pucK[in]           ECC 倍数
 *       pucP[out]          ECC 倍点后的值
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_pointMul_ECC (
	void *hDeviceHandle,
	ECCrefPublicKey *pucG,
	ECCrefPrivateKey *pucK,
	ECCrefPublicKey *pucP);

/*
 *描述： 请求密码设备 通过私钥获得公钥
 *参数： hDeviceHandle[in]  与设备建立的会话句柄
 *       pucPrivateKey[in] ECC 私钥结构
 *       pucPublicKey[out]  ECC 公钥结构
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_GeneratePublicKey_ECC (
	void *hDeviceHandle,
	ECCrefPrivateKey *pucPrivateKey,
	ECCrefPublicKey *pucPublicKey);

/*
 *描述： 请求密码设备产生 ECC 密钥对
 *参数： hDeviceHandle[in]  与设备建立的会话句柄
 *       pucPublicKey[out]  ECC 公钥结构
 *       pucPrivateKey[out] ECC 私钥结构
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_GenerateKeyPair_ECC (
	void *hDeviceHandle,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey);

/*
 * 描述： 使用外部 ECC 私钥对数据进行签名运算
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        pucPrivateKey[in]  外部 ECC 私钥结构
 *        pucData[in]        缓冲区指针，用于存放外部输入的数据
 *        uiDataLength[in]   输入的数据长度
 *        pucSignature[out]  缓冲区指针，用于存放输出的签名值数据
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_ExternalSign_ECC (
	void *hDeviceHandle,
	ECCrefPrivateKey *pucPrivateKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	ECCSignature *pucSignature);

/*
 * 描述： 使用外部 ECC 公钥对 ECC 签名值进行验证运算
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        pucPublicKey[in]   外部 ECC 公钥结构
 *        pucData[in]        缓冲区指针，用于存放外部输入的数据
 *        uiDataLength[in]   输入的数据长度
 *        pucSignature[in]   缓冲区指针，用于存放输入的签名值数据
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_ExternalVerify_ECC (
	void *hDeviceHandle,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucDataInput,
	unsigned int uiInputLength,
	ECCSignature *pucSignature);

/*
 * 描述： 使用外部 ECC 公钥对数据进行加密运算
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        pucPublicKey[in]   外部 ECC 公钥结构
 *        pucData[in]        缓冲区指针，用于存放外部输入的数据
 *        uiDataLength[in]   输入的数据长度
 *        pucEncData[out]    缓冲区指针，用于存放输出的数据密文
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_ExternalEncrytp_ECC (
	void *hDeviceHandle,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData);

/*
 * 描述： 使用外部 ECC 私钥进行解密运算
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        uiAlgID[in]        算法标识，指定使用的 ECC 算法
 *        pucPrivateKey[in]  外部 ECC 私钥结构
 *        pucEncData[in]     缓冲区指针，用于存放输入的数据密文
 *        pucData[out]       缓冲区指针，用于存放输出的数据明文
 *        puiDataLength[out] 输出的数据明文长度
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_ExternalDecrypt_ECC (
	void *hDeviceHandle,
	ECCrefPrivateKey *pucPrivateKey,
	unsigned char *pucEncData,
	unsigned int uiDataLen,
	unsigned char *pucData);

/*
 * 描述： 使用指定的密钥和 IV 对数据进行对称加密运算
 * 参数： hDeviceHandle[in]     与设备建立的会话句柄
 *        hpucKey[in]           指定的密钥句柄
 *        uiAlgID[in]           算法标识，指定对称加密算法
 *        pucIV[in|out]         缓冲区指针，用于存放输入和返回的 IV 数据
 *        pucData[in]           缓冲区指针，用于存放输入的数据明文
 *        uiDataLength[in]      输入的数据明文长度
 *        pucEncData[out]       缓冲区指针，用于存放输出的数据密文
 *        puiEncDataLength[out] 输出的数据密文长度
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_Encrypt (
	void *hDeviceHandle,
	void *pucKey,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucData,
	unsigned int uiDataLength,
	unsigned char *pucEncData,
	unsigned int *puiEncDataLength);

/*
 * 描述： 使用指定的密钥句柄和 IV 对数据进行对称解密运算
 * 参数： hDeviceHandle[in]   与设备建立的会话句柄
 *        hpucKey[in]         指定的密钥句柄
 *        uiAlgID[in]         算法标识，指定对称加密算法
 *        pucIV[in|out]       缓冲区指针，用于存放输入和返回的 IV 数据
 *        pucEncData[in]      缓冲区指针，用于存放输入的数据密文
 *        uiEncDataLength[in] 输入的数据密文长度
 *        pucData[out]        缓冲区指针，用于存放输出的数据明文
 *        puiDataLength[out]  输出的数据明文长度
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_Decrypt (
	void *hDeviceHandle,
	void *pucKey,
	unsigned int uiAlgID,
	unsigned char *pucIV,
	unsigned char *pucEncData,
	unsigned int uiEncDataLength,
	unsigned char *pucData,
	unsigned int *puiDataLength);

/*
 * 描述： 三步式数据杂凑运算第一步。
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        pucPublicKey[in]   签名者的ECC公钥，产生用于ECC签名的杂凑值时有效
 *        pucID[in]          签名者的ID值， 产生用于ECC签名的杂凑值时有效
 *        uiIDLength[in]     签名者的ID长度
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_HashInit (
	void *hDeviceHandle,
	ECCrefPublicKey *pucPublicKey,
	unsigned char *pucID,
	unsigned int uiIDLength);

/*
 * 描述： 三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        pucData[in]        缓冲区指针，用于存放输入的数据明文
 *        uiDataLength[in]   输入的数据明文长度
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_HashUpdate (
	void *hDeviceHandle,
	unsigned char *pucData,
	unsigned int uiDataLength);

/*
 * 描述： 三步式数据杂凑运算第三步，杂凑运算结束返回杂凑数据并清除中间数据
 * 参数： hDeviceHandle[in]  与设备建立的会话句柄
 *        pucHash[out]       缓冲区指针，用于存放输出的杂凑数据
 *        puiHashLength[out] 返回的杂凑数据长度
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_HashFinal (
	void *hDeviceHandle,
	unsigned char *pucHash,
	unsigned int *puiHashLength);

/*
 * 描述： 使用 ECC 密钥协商算法，为计算会话密钥而产生协商参数，同时返回自己 ECC
 *           公钥、临时 ECC 密钥对的公钥及协商柄。
 * 参数： hDeviceHandle[in]        与设备建立的会话句柄
 *        pucSponsePrivateKey[in]  密码设备加密私钥，该私钥用于参与密钥协商
 *        pucSelfPublicKey[in]     密码设备加密公钥，该私钥用于参与密钥协商
 *        uiKey[in]            要求协商的密钥字节长度
 *        pucSponsorID[in]         参与密钥协商的发起方 ID 值
 *        uiSponsorIDLength[in]    发起方 ID 长度
 *        pucSelfTmpPublicKey[out] 返回的发起方临时 ECC 公钥结构
 *        phAgreementHandle[out]   返回的协商句柄，用于计算协商密钥
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_GenerateAgreementDataWithECC (
	void *hDeviceHandle,
	ECCrefPrivateKey *pucSponsePrivateKey,
	ECCrefPublicKey *pucSponsorPublicKey,
	unsigned int uiKey,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	void **phAgreementHandle);

/*
 * 描述： 使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同
 *           时返回会话密钥。
 * 参数： hDeviceHandle[in]           与设备建立的会话句柄
 *        pucResponseID[in]           外部输入的响应方 ID 值
 *        uiResponseIDLength[in]      外部输入的响应方 ID 长度
 *        pucResponsePublicKey[in]    外部输入的响应方 ECC 公钥结构
 *        pucResponseTmpPublicKey[in] 外部输入的响应方临时 ECC 公钥结构
 *        hAgreementHandle[in]        协商句柄，用于计算协商密钥
 *        phKey[out]                  返回的密钥数据
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_GenerateKeyWithECC (
	void *hDeviceHandle,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	ECCrefPublicKey *pucResponsePublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *hAgreementHandle,
	void *phKey);

/*
 * 描述： 使用ECC密钥协商算法，产生协商参数并计算会话密钥，同时返回产生的协商参数和密钥。
 * 参数： hDeviceHandle[in]            与设备建立的会话句柄
 *        pucResponsePrivateKey[in]    密码设备加密私钥，该私钥用于参与密钥协商
 *        pucResponsePublicKey[in]     密码设备加密公钥，该私钥用于参与密钥协商
 *        uiKey[in]                    协商后要求输出的密钥字节长度
 *        pucResponseID[in]            响应方 ID 值
 *        uiResponseIDLength[in]       响应方 ID 长度
 *        pucSponsorID[in]             发起方 ID 值
 *        uiSponsorIDLength[in]        发起方 ID 长度
 *        pucSponsorPublicKey[in]      外部输入的发起方 ECC 公钥结构
 *        pucSponsorTmpPublicKey[in]   外部输入的发起方临时 ECC 公钥结构
 *        pucResponseTmpPublicKey[out] 返回的响应方临时 ECC 公钥结构
 *        phKey[out]                   返回的密钥数据
 *返回值： 0 成功
 *         非 0 失败，返回错误代码
 */
extern int GMALG_GenerateAgreementDataAndKeyWithECC(
	void *hDeviceHandle,
	ECCrefPrivateKey *pucResponsePrivateKey,
	ECCrefPublicKey *pucResponsePublicKey,
	unsigned int uiKey,
	unsigned char *pucResponseID,
	unsigned int uiResponseIDLength,
	unsigned char *pucSponsorID,
	unsigned int uiSponsorIDLength,
	ECCrefPublicKey *pucSponsorPublicKey,
	ECCrefPublicKey *pucSponsorTmpPublicKey,
	ECCrefPublicKey *pucResponseTmpPublicKey,
	void *phKey);
#endif
