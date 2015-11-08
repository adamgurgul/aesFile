//============================================================================
// Name        : aesFile.cpp
// Author      : agurgul
// Version     :
// Copyright   : All rights reserved
// Description : AES file en/deCryption with openssl implementation.
//============================================================================

#include <iostream>
#include <openssl/aes.h>
#include <cstdio>
#include <cstdlib>
#include <windows.h>
#include <conio.h>
#include <fstream>
using namespace std;

void encryptFile(unsigned char ckey[], unsigned char ivec[], FILE* ifp, FILE* efp, int enc) {
	int bytes_read;
	unsigned char input[AES_BLOCK_SIZE];
	unsigned char output[AES_BLOCK_SIZE];

	AES_KEY key;
	AES_set_encrypt_key(ckey, 128, &key);
	AES_set_decrypt_key(ckey, 128, &key);

	int num = 0;
	while (1) {
		bytes_read = fread(input, 1, AES_BLOCK_SIZE, ifp);
		AES_cfb128_encrypt(input, output, bytes_read, &key, ivec, &num, enc);
		fwrite(output, 1, bytes_read, efp);
		if (bytes_read < AES_BLOCK_SIZE)
			break;
	}
}
int main(int argc, char* argv[]) {
	string key;
	char* inF;
	char* outF;
	if (argc < 4) {
		cout << "This application needs three arguments:" << endl;
		cout << "1. Input file," << endl << "2. Output file" << endl << "3. 1 for encryption, 0 for decryption." << endl;
		cout << "Usage example: aesFile.exe inputFile outputFile 1" << endl;
		return 0;
	}
	inF = argv[1];
	outF = argv[2];
	int encrypt = atoi(argv[3]);
	    key = "";
	    cout << "Input password:" << endl;
	    char c = ' ';
	    while (c!=13) {
	        c = getch();
	        if (c!=13) {
	            key += c;
	            cout << "*";
	        }
	    }
	    cout << endl;


		/*string keyid;
		string pass;
		cout << "Enter id for key" << endl;
		//cin >> keyid;
		cout << "Enter password for key \'" << keyid << "\':" << endl;
		//cin >> pass;
		*/
		//char key[32];
	    unsigned char ckey[] =  "thiskeyisverybad";
	    unsigned char ivec[] = "dontusethisinput";
		//unsigned char ckey[17];
		//unsigned char ivec[17];
		cout << "ok";
		for (int i = 0; i < 16; i++) {
			ckey[i] = key[i];
			ivec[i] = key[i + 16];
			cout << i << endl;
		}
		cout << "tu bylem";
		ckey[16] = '\0';
		ivec[16] = '\0';

		FILE *ifp = fopen(inF, "rb");
		FILE *efp = fopen(outF, "wb");
		encryptFile(ckey, ivec, ifp, efp, encrypt);
		fclose(ifp);
		fclose(efp);

	return 0;
}
