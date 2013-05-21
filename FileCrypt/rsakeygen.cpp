#include "keygenerators.h"
using namespace filecrypt::keygen;
using namespace std;

void RsaKeyGenerator::GenerateRsaKeys(RSA::PrivateKey& pPrivateKey, RSA::PublicKey& pPublicKey, const unsigned int key_length)
{
	AutoSeededRandomPool *rng = new AutoSeededRandomPool();
	pPrivateKey.GenerateRandomWithKeySize(*rng, key_length);
	RSA::PublicKey *p = new RSA::PublicKey(pPrivateKey);
	pPublicKey = *p;
}



void RsaKeyGenerator::GenerateDsaKeys(DSA::PrivateKey& pPrivateKey, DSA::PublicKey& pPublicKey, const unsigned int key_length)
{
	AutoSeededRandomPool *rng = new AutoSeededRandomPool();
	pPrivateKey.GenerateRandomWithKeySize(*rng, key_length);
	pPrivateKey.MakePublicKey(pPublicKey);
}