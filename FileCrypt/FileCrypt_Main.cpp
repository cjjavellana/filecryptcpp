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
using filecrypt::keygen::AesKeyGenerator;
using filecrypt::keygen::RsaKeyGenerator;

#include "fileencryptors.h"
using filecrypt::encryptors::AesFileEncryptor;

#include "keymgt.h"
using filecrypt::keymgt::KeyManager;

#include "rsa.h"
using CryptoPP::RSA;

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

	
	cout << "Generate Rsa Keys..." << endl;
	RSA::PublicKey *pPublicKey = new RSA::PublicKey();
	RSA::PrivateKey *pPrivateKey = new RSA::PrivateKey();
	RsaKeyGenerator *pRsaKeyGen = new RsaKeyGenerator();

	pRsaKeyGen->GenerateRsaKeys(*pPrivateKey, *pPublicKey, 2048);
	

	cout << "Writing encryption key" << endl;
	KeyManager *pKeyManager = new KeyManager();
	cout << "Writing Encryption Key: " << HexUtils::hexify(pAesKey) << "; IV: " << HexUtils::hexify(pAesIv) << endl;
	pKeyManager->EncryptAesKeyAndIvAndEmbedToFile(pPublicKey,pOutputFile,pAesKey,pAesIv,AES::MAX_KEYLENGTH,AES::BLOCKSIZE);
	pKeyManager->SavePrivateKey("C:\\ppk1.key", *pPrivateKey);
	pKeyManager->SavePublicKey("C:\\pub1.pub", *pPublicKey);
	delete pKeyManager;

	cout << "Destroying objects..." << endl;
	pKeyGen->~AesKeyGenerator();

	AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor e(*pPublicKey);
    

	static const int SIZE = AES::MAX_KEYLENGTH; 
	SecByteBlock plaintext(SIZE); 
	//byte block[SIZE]; 
	//rng.GenerateBlock(block, SIZE); 
	memcpy(plaintext, pAesKey, SIZE); 
	for(int x = 0; x < SIZE; x++) { 
		printf("%X%X", (pAesKey[x] & 240) >> 4, (pAesKey[x] & 15)); 
	} 
	cout << endl; 
	size_t ecl = e.CiphertextLength(plaintext.size()); 
	SecByteBlock ciphertext(ecl); 
	e.Encrypt(rng, plaintext, plaintext.size(), ciphertext); 

	cout << "Encrypted AES Key: " << HexUtils::hexify(ciphertext, ciphertext.size()) << endl;

	RSAES_OAEP_SHA_Decryptor d(*pPrivateKey);

	size_t dpl = d.MaxPlaintextLength(ciphertext.size()); 
	SecByteBlock recovered(d.MaxPlaintextLength(ciphertext.size())); 
	DecodingResult result = d.Decrypt(rng, ciphertext, ciphertext.size(), recovered); 
	recovered.resize(result.messageLength); 
	assert(plaintext == recovered); 
	for(int x = 0; x < SIZE; x++) { 
		printf("%X%X", (plaintext[x] & 240) >> 4, (plaintext[x] & 15)); 
	} 
	cout << endl;

    //CryptoPP::RSAES_OAEP_SHA_Decryptor d(*pPrivateKey);
    //CryptoPP::StringSource( cipher, true, new CryptoPP::PK_DecryptorFilter( rng, d, new CryptoPP::StringSink( decrypted_data )));

	//cout << cipher;

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

