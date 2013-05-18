#include <iostream>
#include <fstream>
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

#include "fileencryptors.h"
using filecrypt::encryptors::AesFileEncryptor;

#include "hexutils.h"
using filecrypt::utils::HexUtils;

#include <regex>

// Crypto++ Library
#ifdef _DEBUG
#  pragma comment ( lib, "cryptlibd" )
#else
#  pragma comment ( lib, "cryptlib" )
#endif




int main(int argc, char* argv[]) 
{
	byte pAesKey[AES::MAX_KEYLENGTH], pAesIv[AES::BLOCKSIZE];

	cout << "Generating AES Encryption Key" << endl;

	AesKeyGenerator *pKeyGen = new AesKeyGenerator(AES::MAX_KEYLENGTH, AES::BLOCKSIZE);
	pKeyGen->GenerateKeyAndIv(pAesKey, pAesIv);

	const char *pInputFile = "C:/shared.log", *pOutputFile = "C:/encrypted.log",  *pDecryptedFile = "C:/decrypted.log";

	cout << "Encrypting input file..." << endl;
	AesFileEncryptor *pAesFileEncrytor = new AesFileEncryptor();
	pAesFileEncrytor->EncryptFile(pInputFile,  new FileSink((const char *)pOutputFile, true), pAesKey, pAesIv);
	//pAesFileEncrytor->DecryptFile(pOutputFile, new FileSink(pDecryptedFile, true), pAesKey, pAesIv);

	cout << "Writing encryption key" << endl;

	//append aes key to the end of the encrypted file
	//aes key can be found in the last 32 bytes of the encrypted file
	ofstream *pEncryptedFile = new ofstream(pOutputFile, ios::out | ios::app | ios::binary);
	//file successfully opened
	if(pEncryptedFile->is_open())
	{
		cout << "Writing Encryption Key: " << HexUtils::hexify(pAesKey) << "; IV: " << HexUtils::hexify(pAesIv) << endl;
		byte ekey_marker[] = {0x41,0x41,0x41};
		pEncryptedFile->write((const char *)ekey_marker, 3);
		pEncryptedFile->write((const char *)pAesKey, AES::MAX_KEYLENGTH);

		byte iv_marker[] = {0x42,0x42,0x42};
		pEncryptedFile->write((const char *)iv_marker, 3);
		pEncryptedFile->write((const char *)pAesIv, AES::BLOCKSIZE);

		pEncryptedFile->close();
	}

	cout << "Destroying objects..." << endl;
	delete pEncryptedFile;
	pKeyGen->~AesKeyGenerator();
	
	/**
	cout << "File Decryption Initiated..." << endl;
	ifstream *pFileToDecrypt = new ifstream(pOutputFile, ios::in|ios::binary|ios::ate);
	if(pFileToDecrypt->is_open())
	{
		//declare the variable that will hold the last 32 bytes of the file, which is the key required to decrypt
		char pDecryptionKey[AES::MAX_KEYLENGTH]; 
		char pDecryptionIv[AES::BLOCKSIZE];

		int size = (int) pFileToDecrypt->tellg();

		//read the IV at the last 16 bytes of the encrypted file
		pFileToDecrypt->seekg(size - AES::BLOCKSIZE, ios::beg);
		pFileToDecrypt->read(pDecryptionIv, AES::BLOCKSIZE);

		//read the encryption key starting at index [length of file - (AES::MAX_KEYLENGTH + AES::BLOCKSIZE)]
		pFileToDecrypt->seekg(size - (AES::MAX_KEYLENGTH + AES::BLOCKSIZE), ios::beg);
		pFileToDecrypt->read(pDecryptionKey, AES::MAX_KEYLENGTH);
		pFileToDecrypt->close();

		string key = HexUtils::hexify(pDecryptionKey);
		cout << "Encryption key Recovered: " << key << "; Iv: " << HexUtils::hexify(pDecryptionIv) << endl;
	}
	delete pFileToDecrypt;
	*/
	return 0;
}

