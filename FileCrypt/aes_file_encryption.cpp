#include "aes_file_encryption.h"

using namespace filecrypt::encryptors;

// ~ Public methods =============================================================
void AesFileEncryptor::EncryptFile(const char *fileToEncrypt, FileSink *pOutputFile, const byte *key, const byte *iv)
{
	ValidateKeyAndIvLength(key, iv);

	if(sizeof(fileToEncrypt) > 0 && FileExist(fileToEncrypt))
	{
		AES::Encryption *pAes = new AES::Encryption(key, AES::MAX_KEYLENGTH);
		CBC_Mode_ExternalCipher::Encryption *pCbcEncryption = new CBC_Mode_ExternalCipher::Encryption(*pAes, iv);
		StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, pOutputFile);
		FileSource *pFileSource = new FileSource(fileToEncrypt, true, pFilter);
	}

};

void AesFileEncryptor::DecryptFile(const char *fileToDecrypt, FileSink *pDecryptedFile, const byte *key, byte *iv)
{
	ValidateKeyAndIvLength(key, iv);

	if(sizeof(fileToDecrypt) > 0)
	{
	}

};


// ~ Private methods =============================================================

void AesFileEncryptor::ValidateKeyAndIvLength(const byte *key, const byte *iv)
{
	int key_len = sizeof(key);
	int iv_len = sizeof(iv);
	if(key_len != AES::MAX_KEYLENGTH || iv_len != AES::BLOCKSIZE)
	{
		throw new exception("Invalid key or iv length.");
	}

};


bool AesFileEncryptor::FileExist(const char *location)
{
	ifstream ifile(location);
	return (bool) ifile;
};