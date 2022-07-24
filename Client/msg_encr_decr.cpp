/* -------------------------==[message encryption]==------------------------- */

string getEncryptedBlock(string session_id, string msg)
{
	static char salt[64];
	while (1)
	{
		getDigit(salt, 64, 0, 10);
		if (!strcmp("0", salt)) { memset(salt, '\0', 64); continue;}
		else break;
	}
	
	string payload = msg;
	string to_be_encrypted = salt + session_id + payload;
	
	if (to_be_encrypted.length() < 1024)
	{
		char * padding = new char [1024 - to_be_encrypted.length() + 1];
		memset(padding, '0', 1024 - to_be_encrypted.length() + 1);
		to_be_encrypted = to_be_encrypted + string(padding);
		to_be_encrypted.erase( remove(to_be_encrypted.begin(), to_be_encrypted.end(), '\n'), to_be_encrypted.end() );
		return to_be_encrypted;
	}
	else return "0";
	
}

string get_msg_key(string plaintext, string auth_key)
{
	 /*
	  *	Message Key (msg_key)
	  *	In MTProto 2.0, the middle 128 bits of the SHA-256 hash of the message to be encrypted (including the internal 
	  *	header and the padding bytes for MTProto 2.0), prepended by a 32-byte fragment of the authorization key.
	  */
	 
	 string msg_key_large = SHA256(auth_key.substr(0+0, 32) + plaintext);
	 string msg_key = msg_key_large.substr(8, 16);
	 return msg_key;
	 
	 
}
 
string get_aes_key(string msg_key, string auth_key)
{
	 /*
	  * The 2048-bit authorization key (auth_key) and the 128-bit message key (msg_key) are used to compute a 256-bit 
	  * AES key (aes_key) and a 256-bit initialization vector (aes_iv) which are subsequently used to encrypt the part of the message to be encrypted
	  */
	 
	 string sha256_a = SHA256 (msg_key + auth_key.substr(0, 36));
	 string sha256_b = SHA256 (auth_key.substr(40+0, 36) + msg_key);
	 string aes_key = sha256_a.substr(0, 8) + sha256_b.substr(8, 16) + sha256_a.substr(24, 8);
	 return aes_key;
}
 
string get_aes_iv(string msg_key, string auth_key)
{
	 /*
	  * The 2048-bit authorization key (auth_key) and the 128-bit message key (msg_key) are used to compute a 256-bit 
	  * AES key (aes_key) and a 256-bit initialization vector (aes_iv) which are subsequently used to encrypt the part of the message to be encrypted
	  */
	 
	 string sha256_a = SHA256 (msg_key + auth_key.substr(0, 36));
	 string sha256_b = SHA256 (auth_key.substr(40+0, 36) + msg_key);
	 string aes_iv = sha256_b.substr(0, 8) + sha256_a.substr(8, 16) + sha256_b.substr(24, 8);
	 return aes_iv;
}

