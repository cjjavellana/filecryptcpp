#include "keygenerators.h"
using namespace filecrypt::keygen;
using namespace std;

void RsaKeyGenerator::GenerateRsaKeys(RSA::PrivateKey *pPrivateKey, RSA::PublicKey *pPublicKey, const unsigned int key_length)
{
	AutoSeededRandomPool *rng = new AutoSeededRandomPool();
	pPrivateKey = new RSA::PrivateKey();
	pPrivateKey->GenerateRandomWithKeySize(*rng, key_length);
	pPublicKey = new RSA::PublicKey(*pPrivateKey);


	///////////////////////////////////////
	// Generated Parameters
	const Integer& n = pPrivateKey->GetModulus();
	const Integer& p = pPrivateKey->GetPrime1();
	const Integer& q = pPrivateKey->GetPrime2();
	const Integer& d = pPrivateKey->GetPrivateExponent();
	const Integer& e = pPrivateKey->GetPublicExponent();

	///////////////////////////////////////
	// Dump
	cout << "RSA Parameters:" << endl;
	cout << " n: " << n << endl;
	cout << " p: " << p << endl;
	cout << " q: " << q << endl;
	cout << " d: " << d << endl;
	cout << " e: " << e << endl;
	cout << endl;

}

void RsaKeyGenerator::SavePrivateKey(const char *filename, const PrivateKey& pPrivateKey)
{
	ByteQueue queue;
    pPrivateKey.Save(queue);

    this->SaveKeyBase64(filename, queue);
}

void RsaKeyGenerator::SavePublicKey(const char *filename, const PublicKey& pPublicKey)
{
	ByteQueue queue;
    pPublicKey.Save(queue);

    this->SaveKeyBase64(filename, queue);
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

void RsaKeyGenerator::GenerateDsaKeys(DSA::PrivateKey *pPrivateKey, DSA::PublicKey *pPublicKey, const unsigned int key_length)
{
	AutoSeededRandomPool *rng = new AutoSeededRandomPool();
	pPrivateKey = new DSA::PrivateKey();
	pPrivateKey->GenerateRandomWithKeySize(*rng, key_length);
	pPublicKey = new DSA::PublicKey();
	pPrivateKey->MakePublicKey(*pPublicKey);
}