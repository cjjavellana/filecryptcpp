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
			int EncryptFile(const char *fileToEncrypt, FileSink *pOutputFile, const byte *key, const byte *iv)
			{
				if(ValidateKeyAndIvLength(key, iv) == 0 && sizeof(fileToEncrypt) > 0 && FileExist(fileToEncrypt))
				{
					AES::Encryption *pAes = new AES::Encryption(key, AES::MAX_KEYLENGTH);
					CBC_Mode_ExternalCipher::Encryption *pCbcEncryption = new CBC_Mode_ExternalCipher::Encryption(*pAes, iv);
					StreamTransformationFilter *pFilter = new StreamTransformationFilter(*pCbcEncryption, pOutputFile);
					FileSource *pFileSource = new FileSource(fileToEncrypt, true, pFilter);
					return 0;		
				}

				return -1;
			};

			int DecryptFile(const char *fileToDecrypt, FileSink *pDecryptedFile, const byte *key, byte *iv)
			{
				if(ValidateKeyAndIvLength(key, iv) == 0 && sizeof(fileToDecrypt) > 0)
				{
				}

				return -1;
			};
		private:
			int ValidateKeyAndIvLength(const byte *key, const byte *iv)
			{
				int key_len = sizeof(key);
				int iv_len = sizeof(iv);
				if(key_len != AES::MAX_KEYLENGTH || iv_len != AES::BLOCKSIZE)
				{
					return -1;
				}

				return 0;
			};

			bool FileExist(const char *location)
			{
				ifstream ifile(location);
				return ifile;
			};
		};
	}
}