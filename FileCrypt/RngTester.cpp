#include <iostream>
#include "RngTester.h"
#include "osrng.h"

using namespace FileCryptTests;
using namespace std;
using namespace CryptoPP;

void RngTester::init_rng(){
	RandomNumberGenerator *pRng = new AutoSeededRandomPool();
	word32 random_word_32 = pRng->GenerateWord32(0, 1000);
	word32 new_random_word =pRng->GenerateWord32(0, 500);
	cout << random_word_32 << ' ' << new_random_word << '\n';
	delete pRng;
}