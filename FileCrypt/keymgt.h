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
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

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
using CryptoPP::Base64Decoder;
using CryptoPP::FileSource;
using CryptoPP::DecodingResult;

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
			
			void LoadPrivateKey(const string &filename, PrivateKey &privateKey);
			void LoadPublicKey(const string &filename, PublicKey &publicKey);

			//Recover the AES Key and IV used to encrypted the file at filename
			// private_key_file - points to the file location of the private key to be used to decrypt the 
			//	embedded keys in the encrypted file
			void RecoverAesKeyAndIv(const char *filename, const char *private_key_file, byte *key, byte *iv);
		private:
			void SaveKeyBase64(const char *filename, const BufferedTransformation& bt);
			void LoadKeyBase64(const string &filename, BufferedTransformation& bt);
			void SaveKey(const char *filename, const BufferedTransformation& bt);
			void LoadKey(const string &filename, BufferedTransformation &bt);
		};
	}
}
