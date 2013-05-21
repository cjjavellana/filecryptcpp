#include "fileencryptors.h"

using namespace filecrypt::encryptors;

// ~ Public methods =============================================================
void AesFileEncryptor::EncryptFile(const char *fileToEncrypt, FileSink *pOutputFile, const byte *key, const byte *iv)
{	
	AES::Encryption *pAes = new AES::Encryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption *pCbcEncryption = new CBC_Mode_ExternalCipher::Encryption(*pAes, iv);
	StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, pOutputFile);
	FileSource *pFileSource = new FileSource(fileToEncrypt, true, pFilter);
};

void AesFileEncryptor::DecryptFile(const char *fileToDecrypt, FileSink *pDecryptedFile, const byte *key, byte *iv)
{
	AES::Decryption *pDecryptor = new AES::Decryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption *pCbcDecryptor = new CBC_Mode_ExternalCipher::Decryption(*pDecryptor, iv);
	StreamTransformationFilter *pDecryptionFilter = new StreamTransformationFilter(*pCbcDecryptor, pDecryptedFile);
	FileSource *pDecryptedFileSource = new FileSource(fileToDecrypt,true,pDecryptionFilter);
};


// ~ Private methods =============================================================

