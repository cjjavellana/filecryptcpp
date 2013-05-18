#include "fileencryptors.h"

using namespace filecrypt::encryptors;

// ~ Public methods =============================================================
void AesFileEncryptor::EncryptFile(const char *fileToEncrypt, FileSink *pOutputFile, const byte *key, const byte *iv)
{
	// some sanity checks
	//ValidateKeyAndIvLength(key, iv);
	//ValidateIfFileExist(fileToEncrypt);
	
	AES::Encryption *pAes = new AES::Encryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption *pCbcEncryption = new CBC_Mode_ExternalCipher::Encryption(*pAes, iv);
	StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, pOutputFile);
	FileSource *pFileSource = new FileSource(fileToEncrypt, true, pFilter);
};

void AesFileEncryptor::DecryptFile(const char *fileToDecrypt, FileSink *pDecryptedFile, const byte *key, byte *iv)
{
	// some sanity checks
	//ValidateKeyAndIvLength(key, iv);
	//ValidateIfFileExist(fileToDecrypt);

	AES::Decryption *pDecryptor = new AES::Decryption(key, AES::MAX_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption *pCbcDecryptor = new CBC_Mode_ExternalCipher::Decryption(*pDecryptor, iv);

	StreamTransformationFilter *pDecryptionFilter = new StreamTransformationFilter(*pCbcDecryptor, pDecryptedFile);
	FileSource *pDecryptedFileSource = new FileSource(fileToDecrypt,true,pDecryptionFilter);
};


// ~ Private methods =============================================================

//TODO: Fix the error in getting the size of the key and iv
void AesFileEncryptor::ValidateKeyAndIvLength(const byte *key, const byte *iv)
{
	int key_len =sizeof(key);
	int iv_len = sizeof(iv);
	if(key_len != AES::MAX_KEYLENGTH || iv_len != AES::BLOCKSIZE)
	{
		throw new exception("Invalid key or iv length.");
	}

};

//TODO: Fix the error in getting the size of *location
void AesFileEncryptor::ValidateIfFileExist(const char *location)
{
	if(sizeof(location) == 0)
	{
		throw new exception("File location cannot be null or empty");
	}

	ifstream ifile(location);
	if(!(bool) ifile)
	{
		char *msg = new char;
		sprintf(msg, "Unable to locate file %s", *location);
		throw new exception(msg);
	}
};