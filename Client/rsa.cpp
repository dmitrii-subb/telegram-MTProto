/* -------------------------==[RAW-RSA Encryption/Decryption with keys generator]==------------------------- */

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue; 

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Integer;
using CryptoPP::byte;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;


 static void Load(const string& filename, BufferedTransformation& bt)
 {
	 /* http://www.cryptopp.com/docs/ref/class_file_source.html */
	 FileSource file(filename.c_str(), true /*pumpAll*/);
	 
	 file.TransferTo(bt);
	 bt.MessageEnd();
 }
 
 static void Save(const string& filename, const BufferedTransformation& bt)
 {
	 /* http://www.cryptopp.com/docs/ref/class_file_sink.html */
	 FileSink file(filename.c_str());
	 
	 bt.CopyTo(file);
	 file.MessageEnd();
 }
 
 static void SavePrivateKey(const string& filename, const PrivateKey& key)
 {
	 /* http://www.cryptopp.com/docs/ref/class_byte_queue.html */
	 ByteQueue queue;
	 key.Save(queue);
	 
	 Save(filename, queue);
 }
 
 static void SavePublicKey(const string& filename, const PublicKey& key)
 {
	 /* http://www.cryptopp.com/docs/ref/class_byte_queue.html */
	 ByteQueue queue;
	 key.Save(queue);
	 
	 Save(filename, queue);
 }
 
static void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	 /* http://www.cryptopp.com/docs/ref/class_byte_queue.html */
	 ByteQueue queue;
	 
	 Load(filename, queue);
	 key.Load(queue);	
}
 
static void LoadPublicKey(const string& filename, PublicKey& key)
{
	 /* http://www.cryptopp.com/docs/ref/class_byte_queue.html */
	 ByteQueue queue;
	 
	 Load(filename, queue);
	 key.Load(queue);	
}
 
void RSAkeyGen(string public_key_name, string private_key_name)
{
	 AutoSeededRandomPool rnd;
	 
	 RSA::PrivateKey rsaPrivate;
	 rsaPrivate.GenerateRandomWithKeySize(rnd, 2048);
	 
	 RSA::PublicKey rsaPublic(rsaPrivate);
	 /* https://www.cryptopp.com/wiki/Keys_and_Formats */
	 SavePrivateKey(private_key_name, rsaPrivate);
	 SavePublicKey(public_key_name, rsaPublic);
	 cout << "Successfully generated and saved RSA keys\n" << endl;
	 
}
 
string RSA_Encrypt(string buf, string key_name)
{
	 AutoSeededRandomPool rnd;
	 RSA::PrivateKey rsaPrivate;
	 RSA::PublicKey rsaPublic;
	 
	 /* https://www.cryptopp.com/wiki/Keys_and_Formats */
	 LoadPublicKey(key_name, rsaPublic);
	 
	 Integer r, c;
	 Integer m((const byte *)buf.data(), buf.size());
	 c = rsaPublic.ApplyFunction(m);
	 
	 ostringstream oss;
	 oss << hex << c;
	 return oss.str();
 }
 
string RSA_Decrypt(string buf, string key_name)
{
	 AutoSeededRandomPool rnd;
	 RSA::PrivateKey rsaPrivate;
	 
	 Integer c(buf.c_str()), r;
	 
	 /* https://www.cryptopp.com/wiki/Keys_and_Formats */
	 LoadPrivateKey(key_name, rsaPrivate);
	 rsaPrivate.Validate(rnd, 3);
	 
	 string message = buf;
	 
	 r = rsaPrivate.CalculateInverse(rnd, c);
	 size_t req = r.MinEncodedSize();
	 
	 message.resize(req);
	 r.Encode((byte *)message.data(), message.size());
	 return message;
} 
