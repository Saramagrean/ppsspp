// Copyright (c) 2012- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#include "Core/HLE/HLE.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/HLE/sceOpenPSID.h"
#include "Core/MemMap.h"
#include <Core/HLE/proAdhoc.h>

u8 dummyOpenPSID[16] = { 0x10, 0x02, 0xA3, 0x44, 0x13, 0xF5, 0x93, 0xB0, 0xCC, 0x6E, 0xD1, 0x32, 0x27, 0x85, 0x0F, 0x9D };

void __OpenPSIDInit() {
	// Making sure the ID is unique
	getLocalMac((SceNetEtherAddr*)&dummyOpenPSID);
	return;
}

void __OpenPSIDShutdown() {

	return;
}

static int sceOpenPSIDGetOpenPSID(u32 OpenPSIDPtr)
{
	ERROR_LOG(HLE, "UNTESTED sceOpenPSIDGetOpenPSID(%08x)", OpenPSIDPtr);

	if (Memory::IsValidAddress(OpenPSIDPtr))
	{
		for (int i = 0; i < 16; i++) 
		{
			Memory::Write_U8(dummyOpenPSID[i], OpenPSIDPtr+i);
		}
	}
	return 0;
}

static int sceOpenPSIDGetPSID(u32 OpenPSIDPtr,u32 unknown)
{
	ERROR_LOG(HLE, "UNTESTED %s(%08x, %08x)", __FUNCTION__, OpenPSIDPtr, unknown);

	if (Memory::IsValidAddress(OpenPSIDPtr))
	{
		for (int i = 0; i < 16; i++)
		{
			Memory::Write_U8(dummyOpenPSID[i], OpenPSIDPtr + i);
		}
	}
	return 0;
}

/*
Decrypt the provided data. The data has to be AES encrypted.

Note:
	The used key is provided by the PSP.

Parameters:
	pSrcData	Pointer to data to decrypt. The decrypted data will be written back into this buffer.
	size	The size of the data to decrypt. The size needs to be a multiple of KIRK_AES_BLOCK_LEN. Max size: SCE_DNAS_USER_DATA_MAX_LEN.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbDecrypt(u32 pSrcDataPtr, SceSize size) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %d)", __FUNCTION__, pSrcDataPtr, size);

	return 0;
}

/*
Encrypt the provided data. It will be encrypted using AES.

Note:
	The used key is provided by the PSP.

Parameters:
	pSrcData	Pointer to data to encrypt. The encrypted data will be written back into this buffer.
	size	The size of the data to encrypt. The size needs to be a multiple of KIRK_AES_BLOCK_LEN. Max size: SCE_DNAS_USER_DATA_MAX_LEN.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbEncrypt(u32 pSrcDataPtr, SceSize size) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %d)", __FUNCTION__, pSrcDataPtr, size);

	return 0;
}

/*
Generate a SHA-1 hash value of the provided data.

Parameters:
	pSrcData	Pointer to data to generate the hash for.
	size	The size of the source data. Max size: SCE_DNAS_USER_DATA_MAX_LEN.
	pDigest	Pointer to buffer receiving the hash. Size: KIRK_SHA1_DIGEST_LEN.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbHash(u32 pSrcDataPtr, SceSize size, u32 pDigestPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %d, %08x)", __FUNCTION__, pSrcDataPtr, size, pDigestPtr);

	return 0;
}

/*
Generate a new (public,private) key pair to use with ECDSA.

Parameters:
	pKeyData	Pointer to buffer receiving the computed key pair.
		The first KIRK_ECDSA_PRIVATE_KEY_LEN byte will contain the private key.
		The rest of the bytes will contain the public key (elliptic curve) point p = (x,y),
		with the x-value being first. Both coordinates have size KIRK_ECDSA_POINT_LEN / 2.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbMul1(u32 pKeyDataPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x)", __FUNCTION__, pKeyDataPtr);

	return 0;
}

/*
Compute a new elliptic curve point by multiplying the provided private key with the
provided base point of the elliptic curve.

Parameters:
	pPrivKey	Pointer to the private key of a (public,private) key pair usable for ECDSA.
	pBasePoint	Pointer to a base point of the elliptic curve. Point size: KIRK_ECDSA_POINT_LEN
	pNewPoint	Pointer to a buffer receiving the new curve point. Buffer size: KIRK_ECDSA_POINT_LEN

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbMul2(u32 pPrivKeyPtr, u32 pBasePointPtr, u32 pNewPointPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %08x, %08x)", __FUNCTION__, pPrivKeyPtr, pBasePointPtr, pNewPointPtr);

	return 0;
}

/*
Verify if the provided signature is valid for the specified data given the public key.

Note:
	The ECDSA algorithm is used to verify a signature.

Parameters:
	pPubKey	The public key used for validating the (data,signature) pair. Size has to be KIRK_ECDSA_PUBLIC_KEY_LEN.
	pData	Pointer to data the signature has to be verified for. Data length: KIRK_ECDSA_SRC_DATA_LEN
	pSig	Pointer to the signature to verify. Signature length: KIRK_ECDSA_SIG_LEN

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbSigvry(u32 pPubKeyPtr, u32 pDataPtr, u32 pSigPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %08x, %08x)", __FUNCTION__, pPubKeyPtr, pDataPtr, pSigPtr);

	return 0;
}

/*
Verify a certificate.

Parameters:
	pCert	Pointer to the certificate to verify. Certificate length: KIRK_CERT_LEN.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbCertvry(u32 pCertPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x)", __FUNCTION__, pCertPtr);

	return 0;
}

/*
Generate a valid signature for the specified data using the specified private key.

Note:
	The ECDSA algorithm is used to generate a signature.

Parameters:
	pPrivKey	Pointer to the private key used to generate the signature. CONFIRM: The key has to be AES encrypted before.
	pSrcData	Pointer to data a signature has to be computed for. Data length: KIRK_ECDSA_SRC_DATA_LEN
	pSig	Pointer to a buffer receiving the signature. Signature length: KIRK_ECDSA_SIG_LEN

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbSiggen(u32 pPrivKeyPtr, u32 pSrcDataPtr, u32 pSigPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %08x, %08x)", __FUNCTION__, pPrivKeyPtr, pSrcDataPtr, pSigPtr);

	return 0;
}

/*
Generate a KIRK_PRN_LEN large pseudorandom number (PRN).

Note:
	The seed is automatically set by the system software.

Parameters:
	pDstData	Pointer to buffer receiving the PRN. Size has to be KIRK_PRN_LEN.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdbPrngen(u32 pDstDataPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x)", __FUNCTION__, pDstDataPtr);

	return 0;
}

/*
Verify if the provided signature is valid for the specified data. The public key
is provided by the system software.

Note:
	The ECDSA algorithm is used to verify a signature.

Parameters:
	pData	Pointer to data the signature has to be verified for. Data length: KIRK_ECDSA_SRC_DATA_LEN.
	pSig	Pointer to the signature to verify. Signature length: KIRK_ECDSA_SIG_LEN.

Returns:
	0 on success, otherwise < 0.
*/
static s32 sceDdrdb_F013F8BF(u32 pDataPtr, u32 pSigPtr) {
	ERROR_LOG(HLE, "UNIMPL %s(%08x, %08x)", __FUNCTION__, pDataPtr, pSigPtr);

	return 0;
}



const HLEFunction sceOpenPSID[] = 
{
	{0XC69BEBCE, &WrapI_U<sceOpenPSIDGetOpenPSID>,   "sceOpenPSIDGetOpenPSID", 'i', "x" },
};

void Register_sceOpenPSID()
{
	RegisterModule("sceOpenPSID", ARRAY_SIZE(sceOpenPSID), sceOpenPSID);
}

// According to https://playstationdev.wiki/pspprxlibraries/5.00/kd/openpsid.xml
// sceOpenPSID_driver library seems to contains a duplicate of sceOpenPSIDGetOpenPSID just like sceOpenPSID library, is this allowed here?
const HLEFunction sceOpenPSID_driver[] =
{
	{0x19D579F0, &WrapI_UU<sceOpenPSIDGetPSID>,      "sceOpenPSIDGetPSID",     'i', "xx" },
	{0XC69BEBCE, &WrapI_U<sceOpenPSIDGetOpenPSID>,   "sceOpenPSIDGetOpenPSID", 'i', "x"  },
	{0xFD7BFE3B, nullptr,   "sceOpenPSID_driver_FD7BFE3B", '?', "" },
};

void Register_sceOpenPSID_driver()
{
	RegisterModule("sceOpenPSID_driver", ARRAY_SIZE(sceOpenPSID_driver), sceOpenPSID_driver);
}

// Based on https://uofw.github.io/uofw/group__OpenPSID.html
const HLEFunction sceDdrdb_driver[] =
{
	{0x05D50F41, &WrapI_UU<sceDdrdbEncrypt>,   "sceDdrdbEncrypt",  'i', "xx"  },
	{0x370F456A, &WrapI_U<sceDdrdbCertvry>,    "sceDdrdbCertvry",  'i', "x"   },
	{0x40CB752A, &WrapI_UUU<sceDdrdbHash>,     "sceDdrdbHash",     'i', "xxx" },
	{0xB24E1391, &WrapI_UUU<sceDdrdbSiggen>,   "sceDdrdbSiggen",   'i', "xxx" },
	{0xB33ACB44, &WrapI_UU<sceDdrdbDecrypt>,   "sceDdrdbDecrypt",  'i', "xx"  },
	{0xB8218473, &WrapI_U<sceDdrdbPrngen>,     "sceDdrdbPrngen",   'i', "x"   },
	{0xE27CE4CB, &WrapI_UUU<sceDdrdbSigvry>,   "sceDdrdbSigvry",   'i', "xxx" },
	{0xEC05300A, &WrapI_UUU<sceDdrdbMul2>,     "sceDdrdbMul2",     'i', "xxx" },
	{0xF970D54E, &WrapI_U<sceDdrdbMul1>,       "sceDdrdbMul1",     'i', "x"   },
};

void Register_sceDdrdb_driver()
{
	RegisterModule("sceDdrdb_driver", ARRAY_SIZE(sceDdrdb_driver), sceDdrdb_driver);
}

const HLEFunction scePcact_driver[] =
{
	{0x08BB9677, nullptr,   "scePcactAuth2BB", '?', "" },
	{0xF9ECFDDD, nullptr,   "scePcactAuth1BB", '?', "" },
};

void Register_scePcact_driver()
{
	RegisterModule("scePcact_driver", ARRAY_SIZE(scePcact_driver), scePcact_driver);
}

const HLEFunction sceMlnpsnl_driver[] =
{
	{0x6885F392, nullptr,   "sceMlnpsnlAuth2BB", '?', "" },
	{0x8523E178, nullptr,   "sceMlnpsnlAuth1BB", '?', "" },
};

void Register_sceMlnpsnl_driver()
{
	RegisterModule("sceMlnpsnl_driver", ARRAY_SIZE(sceMlnpsnl_driver), sceMlnpsnl_driver);
}

const HLEFunction sceDdrdb[] =
{
	{0xF013F8BF, &WrapI_UU<sceDdrdb_F013F8BF>,   "sceDdrdb_F013F8BF", 'i', "xx" },
};

void Register_sceDdrdb()
{
	RegisterModule("sceDdrdb", ARRAY_SIZE(sceDdrdb), sceDdrdb);
}
