/* -------------------------==[auth_key key exchange (DH + COMBINED ENCRYPTION (RAW RSA + AES256) )]==------------------------- */
// The first thing a client application must do is create an authorization key which is normally generated when it is first run and almost never changes.

string db_aes_key = "qwertyuiopasdfghjklzxcvbnmqwerty";
string db_aes_iv = "0123456789123456";

string dh_aes_key = "qwertyuiopasdfghjklzxcvbnmqwerty";
string dh_aes_iv = "0123456789123456"; 

string username;

short getKeySize(const char* file_name){
	short file_size = 0;
	FILE* fd = fopen(file_name, "rb");
	if(fd == NULL) file_size = -1;
	else
	{
		fseek(fd, 0, SEEK_END);
		file_size = ftello(fd);
		fclose(fd);
	}
	return file_size;
}

void getNewSession_server(int sockfd)
{
	cout << "\n(!) starting auth key initialisation\n";
	
	struct package{
		char session_id[64];
		char dh_aes_key[1024];
		char dh_aes_iv[1024];
		char p[2048];
		char g[64];
		char A[2048];
	};
	
	struct package dhparams;
	
	static char session_id[64];
	while (1)
	{
		getDigit(session_id, 64, 0, 10);
		if (!strcmp("0", session_id)) { memset(session_id, '\0', 64); continue;}
		else break;
	}
	strncpy(dhparams.session_id, session_id, 64);
	
	
	/* запоминаем ключ клиента */
	 short key_size = 0;
	 recv(sockfd, &key_size, sizeof(short), 0);	 
	 unsigned char * client_key = new unsigned char [key_size]; 
	 recv(sockfd, client_key, key_size, 0);
	 FILE *data = fopen( ("rsa-client-public_"+to_string(sockfd)+"_.key").c_str() , "wb");
	 if (data == NULL) exit(1);
	 fwrite(client_key, key_size, 1, data);
	 fclose(data);
	 delete [] client_key;
	
	 
	/* генерируем число p */
	char p[2048];
	getDigit(p, 2048, 1, 10);
	strncpy(dhparams.p, p, 2048);
	
	/* генерируем число g */
	static char g[64];
	getDigit(g, 64, 1, 10);
	strncpy(dhparams.g, g, 64);
	
	/* генерируем секретное число а */
	static char a[64];
	while (1)
	{
		getDigit(a, 64, 0, 10);
		if (!strcmp("0", a)) { memset(a, '\0', 64); continue;}
		else break;
	}
	
	/* генерируем число A, шифруем и отправляем клиенту */
	mpz_t A_mpz; mpz_init(A_mpz);
	mpz_t p_mpz; mpz_init_set_str(p_mpz, p, 10);
	mpz_t g_mpz; mpz_init_set_str(g_mpz, g, 10);
	mpz_t a_mpz; mpz_init_set_str(a_mpz, a, 10);
	
	mpz_powm(A_mpz, g_mpz, a_mpz, p_mpz);
	
	static char A[2048];
	mpz_get_str(A, 10, A_mpz);
	
	/* шифрование aes_key aes_iv и передача его клиенту */
	strncpy(dhparams.dh_aes_key, RSA_Encrypt(dh_aes_key, "rsa-client-public_"+to_string(sockfd)+"_.key").c_str(), 1024);
	strncpy(dhparams.dh_aes_iv, RSA_Encrypt(dh_aes_iv, "rsa-client-public_"+to_string(sockfd)+"_.key").c_str(), 1024);
	strncpy(dhparams.A, AES256Encode(A, dh_aes_key, dh_aes_iv).c_str(), 2048);
	
	send(sockfd, &dhparams, sizeof(dhparams), 0);
	
	/* принимаем от пользователя число B и расшифровываем */
	recv(sockfd, &dhparams, sizeof(dhparams), 0);
	
	/* запоминаем число B */
	static char B[2048];
	strncpy(B, AES256Decode(dhparams.A, dh_aes_key, dh_aes_iv).c_str(), 2048);
	
	mpz_t B_mpz; mpz_init(B_mpz);
	mpz_init_set_str(B_mpz, B, 10);
	
	/* вычисляем auth_key */
	mpz_t auth_key_mpz; mpz_init(auth_key_mpz);
	mpz_powm(auth_key_mpz, B_mpz, a_mpz, p_mpz);
	
	static char auth_key[2048];
	mpz_get_str(auth_key, 10, auth_key_mpz);
	
	// запись в бд
	db_insertData_server(sockfd, string(session_id), AES256Encode_db( string(auth_key), db_aes_key, db_aes_iv), "USERS");
	printf("successfully authorization | new session with id: %s\n\n", session_id);
	
}

void getNewSession_client(int sockfd){
	
	char usrname[32];
	cout << "(!) starting new session\n" ;
	cout << "enter your username: ";
	fgets(usrname, 32, stdin);
	username = string(usrname);
	std::string::iterator it = std::remove(username.begin(), username.end(), '\n');
	username.erase(it, username.end());
	
	struct package{
		char session_id[64];
		char dh_aes_key[1024];
		char dh_aes_iv[1024];
		char p[2048];
		char g[64];
		char A[2048];
	};
	
	struct package dhparams;
	
	// генерируем секретное число b
	static char b[64];
	while (1)
	{
		getDigit(b, 64, 0, 10);
		if (!strcmp("0", b)) { memset(b, '\0', 64); continue;}
		else break;
	}
	
	short key_size = getKeySize("rsa-client-public.key");
	FILE *key = fopen("rsa-client-public.key", "rb");
	
	if (key == NULL) exit(1);
	unsigned char * client_key = new unsigned char [key_size]; 
	fread(client_key, key_size, 1, key);
	fclose(key);

	//отправляем публичный ключ клиента серверу
	send(sockfd, &key_size, sizeof(short), 0);
	send(sockfd, client_key, key_size, 0);
	delete [] client_key;
	
	// принимаем от сервера числа p, g, A
	recv(sockfd, &dhparams, sizeof(dhparams), 0);
	
	/* запоминаем session_id */
	static char session_id[64];
	strncpy(session_id, dhparams.session_id, 64);
	
	// запоминаем число А
	static char A[2048];
	dh_aes_key = RSA_Decrypt(dhparams.dh_aes_key, "rsa-client-private.key");
	dh_aes_iv = RSA_Decrypt(dhparams.dh_aes_iv, "rsa-client-private.key");
	strncpy(A, AES256Decode(dhparams.A, dh_aes_key, dh_aes_iv).c_str(), 2048);
	
	// запоминаем число p
	char p[2048];
	strncpy(p, dhparams.p, 2048);
	
	// запоминаем число g
	static char g[64];
	strncpy(g, dhparams.g, 64);
	
	// генерируем число В, шифруем и отправляем серверу
	static mpz_t B_mpz; mpz_init(B_mpz);
	mpz_t p_mpz; mpz_init_set_str(p_mpz, p, 10);
	mpz_t g_mpz; mpz_init_set_str(g_mpz, g, 10);
	mpz_t b_mpz; mpz_init_set_str(b_mpz, b, 10);
	
	mpz_powm(B_mpz, g_mpz, b_mpz, p_mpz);
	
	static char B[2048];
	mpz_get_str(B, 10, B_mpz);
	strncpy(dhparams.A, AES256Encode(B, dh_aes_key, dh_aes_iv).c_str(), 2048);

	send(sockfd, &dhparams, sizeof(dhparams), 0);
	
	// вычисляем auth_key
	mpz_t A_mpz; mpz_init(A_mpz);
	mpz_init_set_str(A_mpz, A, 10);
	
	mpz_t auth_key_mpz; mpz_init(auth_key_mpz);
	mpz_powm(auth_key_mpz, A_mpz, b_mpz, p_mpz);
	
	char auth_key[2048];
	mpz_get_str(auth_key, 10, auth_key_mpz);
	
	/* сохранить auth_key и сохранить id */
	db_insertData_client(string(session_id), string(auth_key), "USER");
	
	printf("successfully authorization | session id: %s | %s\n", session_id, usrname);
}

/* -------------------------==[end: auth_key key exchange (DH+RAW_RSA)]==------------------------- */ 
