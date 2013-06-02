#include "keymgt.h"
#include "constants.h"


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
		ofstream *pEncryptedFile = new ofstream(encryptedFile, ios::out | ios::app | ios::binary);

		//file successfully opened
		if(pEncryptedFile->is_open())
		{
			pEncryptedFile->write((const char *)ekey_marker, 3);
			pEncryptedFile->write((const char *)key, key_size);
			pEncryptedFile->write((const char *)ekey_marker, 3);
			pEncryptedFile->write((const char *)iv, block_size);
			
			pEncryptedFile->close();
		}

		delete pEncryptedFile;
}

void KeyManager::RecoverAesKeyAndIv(const char *filename, const char *private_key_file, byte *key, byte *iv)
{
	ifstream file(filename, ios::in|ios::binary|ios::ate);
	if(file.is_open())
	{
		//variable to contain the last size - search_space bytes of the encrypted file
		char search_space[key_search_space];

		//get the file size
		int file_size = (int) file.tellg();
		
		//read from the end to the beginning
		//load only the last key_search_space bytes
		file.seekg(file_size - key_search_space, ios::beg);

		//put the read bytes into search_space
		file.read(search_space, key_search_space);

		
		byte match_counter = 0;

		//there are 2 keys that we're looking for
		//key 1 = iv
		//key 2 = aes key
		byte key_counter = 0;

		unsigned int iv_index = 0;
		unsigned int key_index = 0;

		//read backwards
		for(unsigned int i = key_search_space; i >= 0; i--)
		{
			//check if we have consecutive 0x41
			if(search_space[i] == 0x41) match_counter++;
			else match_counter = 0;

			if(match_counter == 3) 
			{
				if(iv_index == 0) 
				{
					iv_index = i + 3;
				} 
				else 
				{
					key_index = i + 3;
					//we've found all the we're looking for
					break;
				}
			}
		}

		
		
		string raw_string(search_space);

		unsigned int iv_len = key_search_space - iv_index;
		byte *encrypted_iv = new byte[iv_len];
		memcpy(encrypted_iv, search_space + iv_index, key_search_space - iv_index);		
		cout << "Encrypted Iv: " << HexUtils::to_hex(encrypted_iv, iv_len) << endl;
	
		unsigned int key_len = (iv_index - 3) - key_index;
		byte *encrypted_key = new byte[key_len];
		memcpy(encrypted_key, search_space + key_index, (iv_index - 3) - key_index);		
		cout << "Encrypted Key: " << HexUtils::to_hex(encrypted_key, key_len) << endl;
		
		try
		{
			RSA::PrivateKey rsa_ppk;
			LoadPrivateKey(private_key_file, rsa_ppk);
			RSAES_OAEP_SHA_Decryptor decryptor(rsa_ppk);

			size_t dpl = decryptor.MaxPlaintextLength(key_len); 
			SecByteBlock recovered(decryptor.MaxPlaintextLength(key_len)); 

			AutoSeededRandomPool rng;
			DecodingResult result = decryptor.Decrypt(rng, encrypted_key, key_len, recovered); 
			recovered.resize(result.messageLength); 
			key = recovered.BytePtr();
			cout << "Decrypted Key: " << HexUtils::to_hex(key, recovered.size()) << endl;
		} 
		catch(exception &e)
		{
			cout << e.what() << endl;
		}
		return;
	}
	throw new exception("Unable to open file " + *filename);
}

// Key Saving ==================================================================

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

// Key Loading ==================================================================

void KeyManager::LoadPrivateKey(const string &filename, PrivateKey &privateKey)
{
	ByteQueue queue;
	LoadKeyBase64(filename.c_str(), queue);
	privateKey.Load(queue);
}

void KeyManager::LoadKeyBase64(const string &filename, BufferedTransformation &bt)
{
	Base64Decoder decoder;
	LoadKey(filename, decoder);
	decoder.CopyTo(bt);
	bt.MessageEnd();
}

void KeyManager::LoadKey(const string &filename, BufferedTransformation &bt)
{
	FileSource fs(filename.c_str(), true);
	fs.TransferTo(bt);
	bt.MessageEnd();
}