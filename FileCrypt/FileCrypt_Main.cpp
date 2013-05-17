#include <iostream>
using std::cout;

#include "modes.h"
using CryptoPP::CBC_Mode_ExternalCipher;

#include "aes.h"
using CryptoPP::AES;

#include "files.h"
using CryptoPP::FileSource;

#include "filters.h"
using CryptoPP::StreamTransformationFilter;

#include "keygenerators.h"
using filecrypt::keygen::AesKeyGenerator ;


// Crypto++ Library
#ifdef _DEBUG
#  pragma comment ( lib, "cryptlibd" )
#else
#  pragma comment ( lib, "cryptlib" )
#endif


int main(int argc, char* argv[]) 
{
	byte pAesKey[AES::MAX_KEYLENGTH], pAesIv[AES::BLOCKSIZE];

	AesKeyGenerator *pKeyGen = new AesKeyGenerator(AES::MAX_KEYLENGTH, AES::BLOCKSIZE);
	pKeyGen->GenerateKeyAndIv(pAesKey, pAesIv);

	AES::Encryption *pAes = new AES::Encryption(pAesKey, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption *pCbcEncryption = new CBC_Mode_ExternalCipher::Encryption(*pAes, pAesIv);

	char *pInputFile = "C:/shared.log";
	char *pOutputFile = "C:/shared_out.log";
	
	StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, new FileSink((const char *)pOutputFile, true));

	FileSource *pFileSource = new FileSource((const char *)pInputFile, true, pFilter);
	
	delete pAes;
	delete pCbcEncryption;
	delete pFileSource;

	AES::Decryption *pDecryptor = new AES::Decryption(pAesKey, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption *pCbcDecryptor = new CBC_Mode_ExternalCipher::Decryption(*pDecryptor, pAesIv);

	const char *pDecryptedFile = "C:/decrypted.log";
	StreamTransformationFilter *pDecryptionFilter = new StreamTransformationFilter(*pCbcDecryptor, new FileSink(pDecryptedFile, true));
	FileSource *pDecryptedFileSource = new FileSource(pOutputFile,true,pDecryptionFilter);

	delete pDecryptor;
	delete pCbcDecryptor;

	pKeyGen->~AesKeyGenerator();
	

	return 0;
}