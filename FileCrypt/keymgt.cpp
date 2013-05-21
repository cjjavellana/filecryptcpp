#include "keymgt.h"
using filecrypt::keymgt::KeyManager;

void KeyManager::EncryptAesKeyAndIvAndEmbedToFile(const RSA::PublicKey *pRsaPublicKey, const char *encryptedFile, const byte *key, 
					const byte *iv, const size_t key_size, const size_t block_size)
{
	AutoSeededRandomPool *rng = new AutoSeededRandomPool();
    RSAES_OAEP_SHA_Encryptor *encryptor = new RSAES_OAEP_SHA_Encryptor(*pRsaPublicKey);
	
	SecByteBlock plain_aes_key(key_size); 
	memcpy(plain_aes_key, key, key_size); 
	size_t ecl = encryptor->CiphertextLength(plain_aes_key.size()); 
	SecByteBlock encrypted_aes_key(ecl); 
	encryptor->Encrypt(*rng, plain_aes_key, key_size, encrypted_aes_key); 

	SecByteBlock plain_aes_iv(block_size); 
	memcpy(plain_aes_iv, iv, block_size); 
	size_t ecl_iv = encryptor->CiphertextLength(plain_aes_iv.size()); 
	SecByteBlock encrypted_aes_iv(ecl_iv); 
	encryptor->Encrypt(*rng, plain_aes_iv, block_size, encrypted_aes_iv); 

	this->EmbedAesKeyAndIvToFile(encryptedFile, encrypted_aes_key, encrypted_aes_iv, ecl, ecl_iv);
}

void KeyManager::EmbedAesKeyAndIvToFile(const char *encryptedFile, const byte *key, 
					const byte *iv, const size_t key_size, const size_t block_size)
{
		//append aes key to the end of the encrypted file
		//aes key can be found in the last 32 bytes of the encrypted file
		ofstream *pEncryptedFile = new ofstream(encryptedFile, ios::out | ios::app | ios::binary);
		//file successfully opened
		if(pEncryptedFile->is_open())
		{
			const byte ekey_marker[] = {0x41,0x41,0x41};
			
			pEncryptedFile->write((const char *)ekey_marker, 3);
			pEncryptedFile->write((const char *)key, key_size);
			pEncryptedFile->write((const char *)ekey_marker, 3);
			pEncryptedFile->write((const char *)iv, block_size);
			
			pEncryptedFile->close();
		}

		delete pEncryptedFile;
}

void KeyManager::SavePrivateKey(const char *filename, const PrivateKey& pPrivateKey)
{
	ByteQueue *queue = new ByteQueue();
    pPrivateKey.Save(*queue);

    this->SaveKeyBase64(filename, *queue);
}

void KeyManager::SavePublicKey(const char *filename, const PublicKey& pPublicKey)
{
	ByteQueue *queue = new ByteQueue();
    pPublicKey.Save(*queue);

    this->SaveKeyBase64(filename, *queue);
}

void KeyManager::SaveKeyBase64(const char *filename, const BufferedTransformation &bt)
{
	Base64Encoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    SaveKey(filename, encoder);
}

void KeyManager::SaveKey(const char *filename, const BufferedTransformation &bt)
{
	FileSink *fs = new FileSink(filename);
	bt.CopyTo(*fs);
	fs->MessageEnd();
}