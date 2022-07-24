#include <sqlite3.h>

/* -------------------------==[work with database]==------------------------- */
struct db{
	int sock_id;
	string username;
	string session_id;
	string auth_key;
} db_user_data;

static int callback_key(void *NotUsed, int argc, char **argv, char **azColName)
{
	db_user_data.auth_key = argv[0];
	return 0;
}
static int callback_id(void *NotUsed, int argc, char **argv, char **azColName)
{
	db_user_data.session_id = argv[0];
	return 0;
}
static int callback_debug(void *NotUsed, int argc, char **argv, char **azColName)
{
	for(int i = 0; i<argc; i++) printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	printf("\n");
	return 0;
}

////////////////////////////////////////////////////////////////////////////////

void db_createTable_server(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	/* Создание таблицы для данных пользователей */
	string sql = "CREATE TABLE IF NOT EXISTS "+table_name+" ("          \
	"SOCK_ID            CHAR(64)            NOT NULL," \
	"SESSION_ID         CHAR(64)            NOT NULL," \
	"AUTH_KEY           CHAR(2048)          NOT NULL);";

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

void db_createTable_client(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}
	//else puts("Opened database successfully");

	/* Создание таблицы для данных пользователей */
	string sql = "CREATE TABLE IF NOT EXISTS "+table_name+" ("          \
	"SESSION_ID         CHAR(64)            NOT NULL," \
	"AUTH_KEY           CHAR(2048)          NOT NULL);";

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void db_insertData_server(int sock_id, string session_id, string auth_key, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "INSERT INTO "+ table_name +" (SOCK_ID, SESSION_ID,AUTH_KEY) VALUES (" + std::to_string(sock_id) +"," + session_id + ",'" + auth_key + "'); ";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

void db_insertData_client(string id, string auth_key, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}


	string sql = "INSERT INTO "+ table_name +" (SESSION_ID, AUTH_KEY) VALUES (" + id  + ",'" + auth_key + "'); ";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////


void check_db(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "SELECT * from " + table_name;

	rc = sqlite3_exec(db, sql.c_str(), callback_debug, 0, &zErrMsg);

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void db_getKey_server(int sock_id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "SELECT AUTH_KEY from "+ table_name +" where SOCK_ID=" + std::to_string(sock_id) + "; ";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

void db_getKey_client(string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "SELECT AUTH_KEY from "+ table_name +" where SESSION_ID=" + id + "; ";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void db_get_id(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "SELECT * from "+ table_name +";";

	rc = sqlite3_exec(db, sql.c_str(), callback_id, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

////////////////////////////////////////////////////////////////////////////////

void db_delUser_server(int sock_id, string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "DELETE from "+ table_name +" where SOCK_ID=" + std::to_string(sock_id) + "; ";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

void db_delAll(string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "DELETE from "+ table_name + ";";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}

void db_delUser_client(string id, string table_name)
{
	sqlite3 *db;
	char *zErrMsg = 0;
	int rc;

	/* Open database */
	rc = sqlite3_open("data.db", &db);
	if( rc ) {printf("Can't open database: %s\n", sqlite3_errmsg(db)); exit(1);}

	string sql = "DELETE from "+ table_name +" where SESSION_ID=" + id + "; ";

	rc = sqlite3_exec(db, sql.c_str(), callback_key, 0, &zErrMsg);

	if( rc != SQLITE_OK )
	{
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_close(db);
}
/* -------------------------==[end: work with database]==------------------------- */
