#include "key_generator.h"

using namespace filecrypt::keygen;

byte * AesKeyGenerator::GenerateKey()
{
	byte *key = new byte;
	rnd->GenerateBlock(key, this->key_length);
	
	return key;
}

byte * AesKeyGenerator::GenerateIv()
{
	byte *iv = new byte;
	rnd->GenerateBlock(iv, this->iv_length);

	return iv;
}

void AesKeyGenerator::GenerateKeyAndIv(byte *key, byte *iv)
{
	rnd->GenerateBlock(key, this->key_length);
	rnd->GenerateBlock(iv, this->iv_length);
}