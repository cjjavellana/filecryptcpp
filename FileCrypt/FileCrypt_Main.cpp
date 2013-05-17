#include <iostream>
#include "RngTester.h"
#include "osrng.h"
#include "modes.h"
#include "aes.h"
#include "files.h"
#include "filters.h"
#include "key_generator.h"

// Crypto++ Library
#ifdef _DEBUG
#  pragma comment ( lib, "cryptlibd" )
#else
#  pragma comment ( lib, "cryptlib" )
#endif

using namespace std;
using namespace FileCryptTests;
using namespace CryptoPP;
using namespace filecrypt::keygen;

int main(int argc, char* argv[]) 
{
	//RngTester *tester = new RngTester();
	//tester->init_rng();
	//delete tester;

	byte key[AES::MAX_KEYLENGTH], iv[AES::BLOCKSIZE];
	
	memset(key, 0xFF, AES::MAX_KEYLENGTH);
	memset(iv, 0x00, AES::BLOCKSIZE);

	AES::Encryption *pAes = new AES::Encryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption *pCbcEncryption = new CBC_Mode_ExternalCipher::Encryption(*pAes, iv);

	char *pInputFile = "C:/shared.log";
	char *pOutputFile = "C:/shared_out.log";
	
	//StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, new StringSink(outputText));
	StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, new FileSink((const char *)pOutputFile, true));

	FileSource *pFileSource = new FileSource((const char *)pInputFile, true, pFilter);
	
	delete pAes;
	delete pCbcEncryption;
	delete pFileSource;

	AES::Decryption *pDecryptor = new AES::Decryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption *pCbcDecryptor = new CBC_Mode_ExternalCipher::Decryption(*pDecryptor, iv);

	const char *pDecryptedFile = "C:/decrypted.log";
	StreamTransformationFilter *pDecryptionFilter = new StreamTransformationFilter(*pCbcDecryptor, new FileSink(pDecryptedFile, true));
	FileSource *pDecryptedFileSource = new FileSource(pOutputFile,true,pDecryptionFilter);

	delete pDecryptor;
	delete pCbcDecryptor;
	
	AesKeyGenerator *pKeyGen = new AesKeyGenerator();
	byte *pAesKey = pKeyGen->GenerateKey();
	byte *pIv = pKeyGen->GenerateIv();
	cout << "Key Gen: " << *pAesKey << *pIv;
	
	byte *key256 = new byte, *iv256 = new byte;
	pKeyGen->GenerateKeyAndIv(key256, iv256);

	return 0;
}