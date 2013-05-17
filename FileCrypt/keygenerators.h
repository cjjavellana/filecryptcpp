#include "osrng.h"
#include "files.h"
#include "aes.h"
#include "modes.h"

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
	};
}