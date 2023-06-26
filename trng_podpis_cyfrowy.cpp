#include <iostream>
#include <thread>
#include <bit>
#include <bitset>
#include <cstdint>
#include <fstream>

#include "cryptlib.h"
#include "rsa.h"
#include "randpool.h"
#include "base64.h"
#include "files.h"
#include "sha3.h"
#include "hex.h"

using namespace std;
using namespace CryptoPP;

unsigned int coin;
unsigned long long x64 = 0;
unsigned long long y64 = 0;

bool active = true;
atomic<bool> sync = false;
 
void generator(unsigned int N) {
	thread thread1{ [&]() {
		while (!sync) {}	
		for (unsigned int n = 0; n < N; n++) {
			coin = n % 2;
		}		
		active = false;
	} };

	thread thread2{ [&]() {
		while (!sync) {}
		for (unsigned int n = N; n > 0; n--) {
			coin = n % 2;
		}		
		active = false;
	} };


	thread samplerX{ []() {
		while (!sync) {}
		while (active) {
			unsigned int loc = coin;
			x64 *= 0x1LL;
			x64 |= loc;
			x64 <<= 1;
		}
	} };

	thread samplerY{ []() {
		sync = true;
		while (active) {
			unsigned int loc = coin;
			y64 *= 0x1LL;
			y64 |= loc;
			y64 <<= 1;
		}
	} };

	thread1.join();
	thread2.join();
	samplerX.join();
	samplerY.join();
}

bool folding(unsigned long long B) {
	unsigned long long R = 0;
	unsigned long long T = 0;

	for (unsigned int n = 1; n <= 64; n++) {
		T = B << (64 - n);
		T >>= 63;
		R ^= T;
	}
	return R;
}

unsigned long long get64Bits() {
	unsigned int count = 70;

	unsigned int A = 0;
	unsigned int B = 0;
	unsigned long long C = 0;

	unsigned long long V = 0;

	unsigned long long entropy = 0;
	unsigned int entropyBits = 0;

	while(entropyBits < 64) {
		active = true;
		sync = false;

		generator(count);

		A = folding(x64);
		B = folding(y64);

		if (A == B)
			continue;	

		if (A == 1)
			V = 1;
		else
			V = 0;

		entropy ^= V;
		entropy = rotl(entropy, 1);

		entropyBits++;
	}

	return entropy;
}



void fillBytes(CryptoPP::byte* bytes) {
	unsigned long long randomBits = get64Bits();
	for (int i = 0; i < 8; i++) {
		bytes[i] = randomBits & 0x00000000000000FF;
		randomBits >>= 8;
	}
}

void initateRNG(RandomPool& rng) {
	unsigned int sizeOfSeed = 64;
	CryptoPP::byte* bytes;
	bytes = new CryptoPP::byte[sizeOfSeed];

	for (unsigned int i = 0; i < sizeOfSeed; i += 8) {
		fillBytes(bytes + i);
	}

	rng.IncorporateEntropy(bytes, sizeOfSeed);
}

bool checkFile(string filename) {
	fstream plik;
	plik.open(filename, ios::in || ios::binary);
	if (plik.good()) {
		plik.close();
		return true;
	}
	
	plik.close();
	return false;
}

string generateSHA3(string filename) {
	SHA3_256 hash;

	fstream plik;
	plik.open(filename, ios::binary | ios::in);

	if (!plik.good()) {
		cout << "File error";
		plik.close();
		return "";
	}

	string message;
	string temp;

	while (!plik.eof()) {
		plik >> temp;
		message += temp;
	}

	hash.Update((const CryptoPP::byte*)message.data(), message.size());
	string digest;

	digest.resize(hash.DigestSize());
	hash.Final((CryptoPP::byte*)&digest[0]);

	string hashString;

	StringSource input(digest, true);
	StringSink output(hashString);

	HexEncoder encoder;
	input.CopyTo(encoder);
	encoder.MessageEnd();

	encoder.CopyTo(output);
	output.MessageEnd();

	plik.close();

	return hashString;
}

string sign(string plainText, RandomPool& rng, RSA::PrivateKey& privateKey) {
	string signature, signatureText;

	RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

	StringSource secured(plainText, true, new SignerFilter(rng, signer, new StringSink(signature)));

	StringSource input(signature, true);
	StringSink output(signatureText);

	Base64Encoder encoder;
	input.CopyTo(encoder);
	encoder.MessageEnd();

	encoder.CopyTo(output);
	output.MessageEnd();

	return signatureText;
}

bool verify(string plain, string signature, RSA::PublicKey& publicKey) {
	string decodedSignature;

	StringSource input(signature, true);
	StringSink output(decodedSignature);

	Base64Decoder decoder;
	input.CopyTo(decoder);
	decoder.MessageEnd();

	decoder.CopyTo(output);
	output.MessageEnd();

	RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

	bool result = verifier.VerifyMessage((const CryptoPP::byte*)plain.c_str(), plain.size(), (CryptoPP::byte*)decodedSignature.c_str(), decodedSignature.size());
	return result;
}

string getStringPubKey(RSA::PublicKey& key) {
	string publicKeyString;
	StringSink store(publicKeyString);

	ByteQueue queue;
	key.Save(queue);

	Base64Encoder encoder;
	queue.CopyTo(encoder);
	encoder.MessageEnd();

	encoder.CopyTo(store);
	store.MessageEnd();
	return publicKeyString;
}

string getStringPrivKey(RSA::PublicKey& key) {
	string privateKeyString;
	StringSink store(privateKeyString);

	ByteQueue queue;
	key.Save(queue);

	Base64Encoder encoder;
	queue.CopyTo(encoder);
	encoder.MessageEnd();

	encoder.CopyTo(store);
	store.MessageEnd();

	return privateKeyString;
}

RSA::PublicKey getPubkeyFromString(string pubKeyString) {
	RSA::PublicKey key;
	ByteQueue queue;

	StringSource source(pubKeyString, true);
	Base64Decoder decoder;
	source.CopyTo(decoder);
	decoder.MessageEnd();

	decoder.CopyTo(queue);
	queue.MessageEnd();

	key.Load(decoder);
	
	return key;
}

RSA::PrivateKey getPrivkeyFromString(string privKeyString) {
	RSA::PrivateKey key;
	ByteQueue queue;

	StringSource source(privKeyString, true);
	Base64Decoder decoder;
	source.CopyTo(decoder);
	decoder.MessageEnd();

	decoder.CopyTo(queue);
	queue.MessageEnd();

	key.Load(decoder);

	return key;
}

void saveToFile(string filename, string message) {
	fstream plik;
	plik.open(filename, ios::out | ios::binary);

	if (plik.good())
		plik << message;

	plik.close();
}

string readFromFile(string filename) {	
	fstream plik;
	string message = "", temp = "";
	plik.open(filename, ios::in | ios::binary);

	if (plik.good()) {
		while (!plik.eof()) {
			plik >> temp;
			message += temp;
		}
	}

	plik.close();
	
	return message;
}


int main(int argc, char* argv[]) {
	string filename = "";
	string SHA3 = "";
	string signatureText = "";

	string publicKeyString = "";
	string privateKeyString = "";

	string signature = "";
	string signatureFilename = "";

	string pubKeyFilename = "";

	bool signing = false;
	bool verifying = false;

	bool file = false;
	bool pubKey = false;

	for (int i = 1; i < argc; i++) {

		if(!strcmp(argv[i], "-f")) {
			if ((i + 1) < argc) {
				filename = argv[++i];
				file = true;
			}
			else {
				cout << "Wrong filename";
				return 1;
			}
		}
		else if (!strcmp(argv[i], "-s")) {
			signing = true;
		}
		else if(!strcmp(argv[i], "-v")) {
			if ((i + 1) < argc) {
				signatureFilename = argv[++i];
				verifying = true;
			}
		}
		else if (!strcmp(argv[i], "-pub")) {
			if ((i + 1) < argc) {
				pubKeyFilename = argv[++i];
				pubKey = true;
			}
		}
	}

	RandomPool rng;
	initateRNG(rng);


	if (file) {
		if (!checkFile(filename)) {
			cout << "File not found";
			return 1;
		}
	}

	if (signing && file) {
		RSA::PrivateKey privateKey;

		privateKey.GenerateRandomWithKeySize(rng, 2048);
		RSA::PublicKey publicKey(privateKey);

		publicKeyString = getStringPubKey(publicKey);
		publicKeyString.pop_back();

		privateKeyString = getStringPrivKey(privateKey);
		privateKeyString.pop_back();

		saveToFile("publicKeyString.txt", publicKeyString);
		saveToFile("privateKeyString.txt", privateKeyString);					

		SHA3 = generateSHA3(filename);
		signatureText = sign(SHA3, rng, privateKey);
		signatureText.pop_back();

		saveToFile("sha3.txt", SHA3);
		saveToFile("signature.txt", signatureText);

		cout << "---------SHA3---------" << endl;
		cout << SHA3 << endl;
		cout << endl;

		cout << "------SIGNATURE------" << endl;
		cout << signatureText << endl;
		cout << endl;

		cout << "------PUBLIC-KEY------" << endl;
		cout << publicKeyString << endl;
		cout << endl;

		cout << "------PRIVATE-KEY-----" << endl;
		cout << privateKeyString << endl;
		cout << endl;
	}

	if (verifying && pubKey && file) {
		publicKeyString = readFromFile(pubKeyFilename);

		RSA::PublicKey publicKey = getPubkeyFromString(publicKeyString);
		SHA3 = generateSHA3(filename);

		signature = readFromFile(signatureFilename);

		bool verifyStatus = verify(SHA3, signature, publicKey);

		cout << "---------SHA3---------" << endl;
		cout << SHA3 << endl;
		cout << endl;

		cout << "------PUBLIC-KEY------" << endl;
		cout << publicKeyString << endl;
		cout << endl;

		cout << "-------VERIFY------" << endl;
		if (verifyStatus)
			cout << "Verify success";
		else
			cout << "Verify failed";
		cout << endl;
	}

	return 0;
}