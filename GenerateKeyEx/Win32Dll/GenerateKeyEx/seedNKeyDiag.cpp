//*****************************************************************************
/// @file        seedNKeyXcpWin.c
/// @author      Alex Lunkenheimer (ETAS/PAC-Lr)
/// @responsible author
/// @brief       DLL-Main for Seed'n Key for XCP 
/// @history     2002-09-16,Lr: - draft
///              2003-02-07,Lr: - DLL-API using extern "C" 
///                             - adapted privileges to XCP-Spec V1.0,Rev22
//*****************************************************************************

//*****************************************************************************
//                               includes
//*****************************************************************************
#define OPENSSL_NO_DYNAMIC_ENGINE
#define OPENSSL_API_COMPAT 0x10100000L  // 明確使用 OpenSSL 3.0 API
#define OPENSSL_USE_STATIC_LIBS
//#include <openssl/cmac.h>
#include <openssl/cmac.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <assert.h>
#include "seedNKeyDiag.h"

#include <openssl/rsa.h>

//#include <windows.h>
//#include <stdint.h>


//#include <openssl/cmac.h>
//#include <openssl/evp.h> 
//#include <openssl/aes.h>
//#include <openssl/rand.h>

//*****************************************************************************
//                               variables
//*****************************************************************************

//*****************************************************************************
//                               prototypes
//*****************************************************************************

//*****************************************************************************
/// @fn   DllMain ... Windows DLL entrance point
//*****************************************************************************
// 


KEYGEN_API GenerateKeyEx(
	const unsigned char* ipSeedArray,              /* Array for the seed [in] */
	unsigned int iSeedArraySize,                   /* Length of the array for the seed [in] */
	const unsigned int iSecurityLevel,             /* Security level [in] */
	const char* ipVariant,                         /* Name of the active variant [in] */
	unsigned char* iopKeyArray,                    /* Array for the key [in, out] */
	unsigned int iMaxKeyArraySize,                 /* Maximum length of the array for the key [in] */
	unsigned int& oActualKeyArraySize)             /* Length of the key [out] */
{
	//----------------------ORIGIN----------------------------------------------
	//unsigned char Key[4] = { 0XEB,0,0XEB,0 };
	//unsigned char Seed[4];

	//Seed[0] = ipSeedArray[0];
	//Seed[1] = ipSeedArray[1];
	//Seed[2] = ipSeedArray[2];
	//Seed[3] = ipSeedArray[3];

	////begin calculate key from seed------------------------------------------------------------
	//switch (iSecurityLevel)
	//{
	//case 0x01://for security access with Services 0x27 01 ->0x27 02
	//	break;
	//case 0x03://for security access with Services 0x27 03 -> 0x27 04
	//	break;
	//case 0x05://for security access with Services 0x27 05 -> 0x27 06
	//	break;
	//case 0x09://for security access with Services 0x27 09 ->0x27 0A
	//	break;
	//default:break;
	//}
	////end calculate key from seed------------------------------------------------------------
	////Copy key to the output buffer 
	////Note: The first byte of the key array will be the first key byte of the bus message
	//iopKeyArray[3] = Key[3];
	//iopKeyArray[2] = Key[2];
	//iopKeyArray[1] = Key[1];
	//iopKeyArray[0] = Key[0];
	////setting length of key
	//oActualKeyArraySize = 4;
	//----------------------ORIGIN----------------------------------------------

	//----------------------TEST1----------------------------------------------
	//static const unsigned int AES_KEY[16] = {
	//0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U,
	//0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U
	//};

	//for (int i = 0; i < 16; i++) {
	//	iopKeyArray[i] = ipSeedArray[i] ^ AES_KEY[i];
	//}

	//oActualKeyArraySize = 16;
	//----------------------TEST1----------------------------------------------
	//for (int i = 0; i < 16; i++) {
	//	iopKeyArray[i] = ipSeedArray[i] ^ AES_KEY[i];
	//}
	//oActualKeyArraySize = 16;
	//return 0;

	//----------------------TEST2 AES CMAC----------------------------------------------
//	static const unsigned int AES_KEY[16] = {
//	0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U,
//	0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U };
////	static const unsigned int AES_KEY[16] = {
////0X27, 0X03, 0X27 , 0X03 , 0X27 , 0X03 , 0X27 , 0X03 , 0X27 , 0X03 , 0X27 , 0X03 , 0X27 , 0X03 , 0X27 , 0X03 };
//	CMAC_CTX* ctx = CMAC_CTX_new();
//	if (!ctx) return -2;
//
//
//	if (!CMAC_Init(ctx, AES_KEY, 16, EVP_aes_128_cbc(), NULL)) {
//		CMAC_CTX_free(ctx);
//		return -3;
//	}
//
//
//	if (!CMAC_Update(ctx, ipSeedArray, 16)) {
//		CMAC_CTX_free(ctx);
//		return -4;
//	}
//
//	size_t outlen = 16;
//	if (!CMAC_Final(ctx, iopKeyArray, &outlen)) {
//		CMAC_CTX_free(ctx);
//		return -5;
//	}
//
//	CMAC_CTX_free(ctx);
//	oActualKeyArraySize = 16;
//	return 0;
	//----------------------TEST2 AES CMAC----------------------------------------------
	//----------------------TEST2 AES EBC----------------------------------------------

	//static const unsigned char OEM_KEY[16] = {
	//0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U,
	//0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U, 0xEBU, 0x00U };
	//AES_KEY aesKey;
	//AES_set_encrypt_key(OEM_KEY, 128, &aesKey);
	//AES_ecb_encrypt(ipSeedArray, iopKeyArray, &aesKey, AES_ENCRYPT);

	//oActualKeyArraySize = 16; // 固定輸出 16 位元組
	//---------------------------------------------------------------------------------
	//---------------------------adjestion aes cmac ebc--------------------------------


		// 固定 OEM 金鑰
	//const unsigned char OEM_KEY[16] = {
	//	0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00,
	//	0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00
	//};

	//// 步驟 1: 使用 AES-CMAC 計算 Seed 的 MAC 值
	//unsigned char cmacResult[16];
	//size_t cmacLen;
	//CMAC_CTX* ctx = CMAC_CTX_new();
	//CMAC_Init(ctx, OEM_KEY, 16, EVP_aes_128_cbc(), NULL);
	//CMAC_Update(ctx, ipSeedArray, 16);
	//CMAC_Final(ctx, cmacResult, &cmacLen);
	//CMAC_CTX_free(ctx);

	//// 步驟 2: 將 CMAC 結果與 Seed 進行 XOR 得到最終 Key
	//for (int i = 0; i < 16; i++) {
	//	iopKeyArray[i] = ipSeedArray[i] ^ cmacResult[i];
	//}

	//oActualKeyArraySize = 16;

	//------------------------------------------------------------------------------
	//----------------------------------------------test2------------------------------
	// 固定 OEM_KEY
//const unsigned char OEM_KEY[AES_BLOCK_SIZE] = {
//	0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00,
//	0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00, 0xEB, 0x00
//};
//
//unsigned char temp1[AES_BLOCK_SIZE];
//unsigned char temp2[AES_BLOCK_SIZE];
//AES_KEY aesKey;
//
//// 第一次AES-ECB加密
//AES_set_encrypt_key(OEM_KEY, 128, &aesKey);
//AES_ecb_encrypt(ipSeedArray, temp1, &aesKey, AES_ENCRYPT);
//
//// 第二次AES-ECB加密
//AES_ecb_encrypt(temp1, temp2, &aesKey, AES_ENCRYPT);
//
//// 将第二次加密结果与原始Seed进行XOR
//for (int i = 0; i < AES_BLOCK_SIZE; i++) {
//	iopKeyArray[i] = ipSeedArray[i] ^ temp2[i];
//}
//	oActualKeyArraySize = 16;
//---------------------------------tetst3 chatgpt ---good

		// OEM key
	if (iSecurityLevel == 1) {
		unsigned char oemKey[16] = {
			0xEB, 0x00, 0xEB, 0x00,
			0xEB, 0x00, 0xEB, 0x00,
			0xEB, 0x00, 0xEB, 0x00,
			0xEB, 0x00, 0xEB, 0x00
		};

		CMAC_CTX* ctx = CMAC_CTX_new();
		size_t macLen = 0;

		if (!CMAC_Init(ctx, oemKey, 16, EVP_aes_128_cbc(), NULL)) {
			CMAC_CTX_free(ctx);
			return -2;
		}

		if (!CMAC_Update(ctx, ipSeedArray, iSeedArraySize)) {
			CMAC_CTX_free(ctx);
			return -3;
		}

		if (!CMAC_Final(ctx, iopKeyArray, &macLen)) {
			CMAC_CTX_free(ctx);
			return -4;
		}

		CMAC_CTX_free(ctx);
		oActualKeyArraySize = (unsigned int)macLen;
		return KGRE_Ok;
	}
	//------------------level3:2
	if (iSecurityLevel == 2|| iSecurityLevel == 3) {
		unsigned char oemKey[16] = {
		0xEB, 0x00, 0xEB, 0x00,
		0xEB, 0x00, 0xEB, 0x00,
		0xEB, 0x00, 0xEB, 0x00,
		0xEB, 0x00, 0xEB, 0x00
		};
		if (iSeedArraySize != 8 || iMaxKeyArraySize < 4)
			return false;

		CMAC_CTX* ctx = CMAC_CTX_new();
		size_t outlen = 0;
		unsigned char fullMac[16] = { 0 };

		if (!CMAC_Init(ctx, oemKey,16, EVP_aes_128_cbc(), NULL))
			return false;

		if (!CMAC_Update(ctx, ipSeedArray, iSeedArraySize)) 
			return false;

		if (!CMAC_Final(ctx, fullMac, &outlen))
			return false;

		// 只取前 4 byte 當作 Key 回傳
		memcpy(iopKeyArray, fullMac, 4);
		oActualKeyArraySize = 4;

		CMAC_CTX_free(ctx);
		return KGRE_Ok;
	}


}
void ForceLinkOpenSSL() {
	RSA* r = RSA_new();  // 強制連結 RSA 相關符號
}
KEYGEN_API ASAP1A_CCP_ComputeKeyFromSeed(unsigned char* ipSeedArray,          /* Array for the seed [in] */
	                                     UINT16 iSeedArraySize,               /* Length of the array for the seed [in] */
	                                     unsigned char* opKey,                /* Array for the key [in, out] */     
	                                     UINT16 maxSizeKey,                   /* Maximum length of the array for the key [in] */
	                                     UINT16* opSizeKey)                    /* Length of the key [out] */
{
	*opSizeKey = 4;
	return KGRE_Ok;
}

KEYGEN_API SeedAndKey_Type2(UINT32 ASeed, UINT32* AKey)
{
	return KGRE_Ok;
}

KEYGEN_API SeedAndKey_Type3(void* ASeed, void* AKey)
{
	return KGRE_Ok;
}


