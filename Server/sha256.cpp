/* -------------------------==[SHA256]==------------------------- */

#include <cryptopp/sha.h>

string string_to_hex(string input)
{
	static const char* const lut = "0123456789abcdef";
	size_t len = input.length();
	
	string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

string SHA256(string data)
{
	CryptoPP::byte const* pbData = (CryptoPP::byte*) data.data();
	unsigned int nDataLen = data.size();
	CryptoPP::byte abDigest[CryptoPP::SHA256::DIGESTSIZE];
	CryptoPP::SHA256().CalculateDigest(abDigest, pbData, nDataLen);
	string str = string((char*)abDigest, CryptoPP::SHA256::DIGESTSIZE);
	return string_to_hex(str);
} 

