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

void RsaKeyGenerator::SavePrivateKey(const char *filename, const PrivateKey& pPrivateKey)
{
	ByteQueue *queue = new ByteQueue();
    pPrivateKey.Save(*queue);

    this->SaveKeyBase64(filename, *queue);
}

void RsaKeyGenerator::SavePublicKey(const char *filename, const PublicKey& pPublicKey)
{
	ByteQueue *queue = new ByteQueue();
    pPublicKey.Save(*queue);

    this->SaveKeyBase64(filename, *queue);
}

void RsaKeyGenerator::SaveKeyBase64(const char *filename, const BufferedTransformation &bt)
{
	Base64Encoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    SaveKey(filename, encoder);
}

void RsaKeyGenerator::SaveKey(const char *filename, const BufferedTransformation &bt)
{
	FileSink *fs = new FileSink(filename);
	bt.CopyTo(*fs);
	fs->MessageEnd();
}

void RsaKeyGenerator::GenerateDsaKeys(DSA::PrivateKey& pPrivateKey, DSA::PublicKey& pPublicKey, const unsigned int key_length)
{
	AutoSeededRandomPool *rng = new AutoSeededRandomPool();
	pPrivateKey.GenerateRandomWithKeySize(*rng, key_length);
	pPrivateKey.MakePublicKey(pPublicKey);
}