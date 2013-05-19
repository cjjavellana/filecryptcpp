#include <iostream>
#include "osrng.h"
#include "files.h"
#include "aes.h"
#include "modes.h"
#include "rsa.h"
#include "dsa.h"
#include "base64.h"

using namespace CryptoPP;

namespace filecrypt
{
	namespace keygen
	{
		class AesKeyGenerator
		{
		public:
			AesKeyGenerator(int key_length = AES::DEFAULT_KEYLENGTH, int iv_length = AES::BLOCKSIZE)
			{
				this->key_length = key_length;
				this->iv_length = iv_length;
				InitRandomNumberGenerator();
			}
			~AesKeyGenerator();
			byte *GenerateKey();
			byte *GenerateIv();
			void GenerateKeyAndIv(byte *key, byte *iv);

		private:
			void InitRandomNumberGenerator()
			{
				rnd = new AutoSeededRandomPool();
			}
			int key_length;
			int iv_length;
			AutoSeededRandomPool *rnd;
		};

		//
		class RsaKeyGenerator
		{
		public:
			void GenerateRsaKeys(RSA::PrivateKey& pPrivateKey, RSA::PublicKey& pPublicKey, const unsigned int key_length = 2048);
			void GenerateDsaKeys(DSA::PrivateKey& pPrivateKey, DSA::PublicKey& pPublicKey, const unsigned int key_length = 2048);
			void SavePrivateKey(const char *filename, const PrivateKey& pPrivateKey);
			void SavePublicKey(const char *filename, const PublicKey& pPublicKey);
		private:
			void SaveKeyBase64(const char *filename, const BufferedTransformation& bt);
			void SaveKey(const char *filename, const BufferedTransformation& bt);
		};
	};
}