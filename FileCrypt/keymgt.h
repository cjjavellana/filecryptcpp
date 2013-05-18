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


namespace filecrypt
{
	namespace keymgt
	{
		class EncryptionKeyManager
		{
		public:
			void WriteAesKeyAndIvIntoEncryptedFile(const char *encryptedFile, const byte *key, 
					const byte *iv, const size_t key_size, const size_t block_size);			
		};
	}
}
