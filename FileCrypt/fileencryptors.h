#include <iostream>
#include "files.h"
#include "aes.h"
#include "modes.h"


using namespace CryptoPP;
using namespace std;

namespace filecrypt
{
	namespace encryptors
	{
		class AesFileEncryptor
		{
		public:
			AesFileEncryptor();
			~AesFileEncryptor();
			void EncryptFile(const char *fileToEncrypt, FileSink *pOutputFile, const byte *key, const byte *iv);
			void DecryptFile(const char *fileToDecrypt, FileSink *pDecryptedFile, const byte *key, byte *iv);
		private:
			void ValidateKeyAndIvLength(const byte *key, const byte *iv);
			void ValidateIfFileExist(const char *location);
		};
	};
}