#include "keymgt.h"
using filecrypt::keymgt::EncryptionKeyManager;


void EncryptionKeyManager::WriteAesKeyAndIvIntoEncryptedFile(const char *encryptedFile, const byte *key, 
					const byte *iv, const size_t key_size, const size_t block_size)
{
		//append aes key to the end of the encrypted file
		//aes key can be found in the last 32 bytes of the encrypted file
		ofstream *pEncryptedFile = new ofstream(encryptedFile, ios::out | ios::app | ios::binary);
		//file successfully opened
		if(pEncryptedFile->is_open())
		{
			byte ekey_marker[] = {0x41,0x41,0x41};
			pEncryptedFile->write((const char *)ekey_marker, 3);
			pEncryptedFile->write((const char *)key, key_size);

			byte iv_marker[] = {0x42,0x42,0x42};
			pEncryptedFile->write((const char *)iv_marker, 3);
			pEncryptedFile->write((const char *)iv, block_size);

			pEncryptedFile->close();
		}

		delete pEncryptedFile;
}