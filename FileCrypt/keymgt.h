/*
 * The header file for Encryption Key Management
 *
 *
 */
#include "aes.h"
using CryptoPP::AES;

#include <fstream>
using std::ofstream;

#include <iostream>
using std::cout;

#include "hexutils.h"
using filecrypt::utils::HexUtils;

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::SecByteBlock;

#include "base64.h"
using CryptoPP::BufferedTransformation;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::ByteQueue;
using CryptoPP::Base64Encoder;

namespace filecrypt
{
	namespace keymgt
	{
		class KeyManager
		{
		public:
			//Embeds the AES key and IV into the encrypted file
			//This method is considered unsafe as the security keys are exposed in the file
			void EmbedAesKeyAndIvToFile(const char *encryptedFile, const byte *key, 
				const byte *iv, const size_t key_size, const size_t block_size);

			//Encrypts the AES Key and IV with the specified RSA Public key and embeds the ciphers into the encrypted file
			void EncryptAesKeyAndIvAndEmbedToFile(const RSA::PublicKey *pRsaPublicKey, const char *encryptedFile, const byte *key, const byte *iv, const size_t key_size, const size_t block_size);

			void SavePrivateKey(const char *filename, const PrivateKey& pPrivateKey);
			void SavePublicKey(const char *filename, const PublicKey& pPublicKey);

		private:
			void SaveKeyBase64(const char *filename, const BufferedTransformation& bt);
			void SaveKey(const char *filename, const BufferedTransformation& bt);
		};
	}
}
