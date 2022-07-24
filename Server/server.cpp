#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <thread>
#include <iostream>
#include <sstream>
#include <iomanip>
using namespace std;


#include "digits.cpp"
#include "sha256.cpp"
#include "rsa.cpp"
#include "aes.cpp"
#include "database.cpp"
#include "keyExchange.cpp"
#include "msg_encr_decr.cpp"

/*

 * компиляция: g++ server.cpp -o server -lgmpxx -lgmp -pthread -lcryptopp -lsqlite3
 * запуск:     ./server 127.0.0.1 8080
 *            адрес сервера /\     /\ порт, на котором работает сервер

*/

/* -------------------------==[work with messages]==------------------------- */

void makeDir(string dir)
{
	int err_code = 0;
	err_code = system( ("mkdir -p" + dir).c_str() );
	printf("%d\n", err_code);
}

void sendMsg(int *recipient_socket, int sender_socket)
{
	/* соединение первого пользователя со вторым */
	struct package
	{
		char sender_session_id[2048];
		char recipient_session_id[2048];
		int msg_len;
		char sender_username[32];
		char msg_key[2048];
		char encrypted_data[2048];
	}data;

	int recv_len = 0, send_value = 0;
	string db_decryption_aes_key = "qwertyuiopasdfghjklzxcvbnmqwerty";
	string db_decryption_aes_iv = "0123456789123456";

	while( recv_len != -1 || send_value != -1 )
	{
		recv_len = recv(sender_socket, &data, sizeof(data), 0);

		db_getKey_server(sender_socket, "USERS");
		string sender_auth_key = db_user_data.auth_key;
		sender_auth_key = AES256Decode_db(sender_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);

		string aes_key = get_aes_key( string(data.msg_key), sender_auth_key);
		string aes_iv = get_aes_iv( string(data.msg_key), sender_auth_key);
		string decrypted_data = AES256Decode( string(data.encrypted_data), aes_key, aes_iv);

		sender_auth_key = "0000";

		cout << data.sender_username << " : " << decrypted_data.substr(38, data.msg_len) + "\n";

		for (int i = 0; i < 10; i++)
		{
			if (sender_socket != recipient_socket[i] && recipient_socket[i] != 0)
			{
				db_getKey_server(recipient_socket[i], "USERS");
				string recipient_auth_key = db_user_data.auth_key;
				recipient_auth_key = AES256Decode_db(recipient_auth_key, db_decryption_aes_key,  db_decryption_aes_iv);

				aes_key = get_aes_key(string(data.msg_key), recipient_auth_key);
				aes_iv = get_aes_iv(string(data.msg_key), recipient_auth_key);
				strcpy(data.encrypted_data, AES256Encode(decrypted_data, aes_key, aes_iv).c_str() );

				recipient_auth_key = "0000";

				send_value = send(recipient_socket[i], &data, sizeof(data), 0);
			}
		}

	}

}
/* -------------------------==[end: work with messages]==------------------------- */


/* -------------------------==[work with clients]==------------------------- */
int main(int argc, char **argv)
{
	if (argc > 3 || argc < 2)
	{
		printf("Using: %s <ip_address> <port> or %s keygen\n", argv[0], argv[0]);
		exit(1);
	}
	cout << "MTproto: cloud chat (server-client encryption)" << endl << endl;

	db_createTable_server("USERS");
	db_delAll("USERS");    // очистка бд

    /* генерируем PublicKey PrivateKey сервера */
	if ( !strcmp(argv[1], "keygen") )
	{
		RSAkeyGen("rsa-server-public.key", "rsa-server-private.key");
		exit(1);
	}

  char host_ip[16];                   /* ip хоста   */
  strncpy(host_ip, argv[1], 16);
	short host_port = atoi(argv[2]);    /* порт хоста */
	int sockfd = 0;

  struct sockaddr_in client_addr, host_addr;
  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (inet_pton(AF_INET, host_ip, &host_addr.sin_addr) <= 0)
		{ perror("address parsing"); return 1; }

  host_addr.sin_port = htons(host_port);
  host_addr.sin_family = AF_INET;

  if( bind(sockfd, (struct sockaddr*)&host_addr, sizeof(host_addr)) < 0)
		{ perror("bind"); return 2; }

  printf("server: running  | server ip (%s) on port %d\n", host_ip, host_port);

  if (listen(sockfd, 2) == -1)
		{ perror("listening on socket"); return 3; }

  int  sockets[10] = {0}, i = 0;        /* дескрипторы сокетов клиентов      */
  int  new_socket = 0;           		  /* дескриптор сокета нового клиента  */

  while (1)
  {
		if (feof(stdin))
		{
			for (int i = 0; i < 10; i++)
				close(sockets[i]);
				exit(-2);
		}
      socklen_t size = sizeof(struct sockaddr_in);
      new_socket = accept(sockfd, (struct sockaddr*)&client_addr, &size);

      if (new_socket < 0)
			{
				perror("new socket");
				exit(-4);
			}

		printf("server: got new connection | %s:8080 | sockfd -> %d\n",
			inet_ntoa(client_addr.sin_addr), new_socket);

		if (i+1 > 10)
			{ cout << "group full of users" << endl; continue; }

		sockets[i] = new_socket;
		getNewSession_server(sockets[i++]);

		thread data_stream(sendMsg, sockets, new_socket);
		data_stream.detach();

  }

  for (int i = 0; i < 10; i++)
    close(sockets[i]);

  return 0;
}
