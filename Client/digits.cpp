#include <cmath>
#include <gmpxx.h>

/* digit - сюда записывается результат
 * bits  - количество битов
 * mode  - если 1, то вырабатывать простое, если 0, то вырабатывать составное
 * base  - если 10, вернуть число в DEC, если 16, вернуть число в HEX
 */

/* -------------------------==[digits generator]==------------------------- */
char *getDigit(char *digit, int16_t bits, int16_t mode, int16_t base){

	char hex_char[8];   				  /*char in hex format             */
	char * hex_str = new char [bits];   /* string of bytes in hex format */

	FILE *random = fopen("/dev/urandom", "rb");
	if (random == NULL) exit(2);

	int c = 0 ;
	static mpz_t digit_dec_str;
	
	while (1)
	{
		for (int i = 0; i < bits/8;)
		{
			c = fgetc(random);
			if (c >= '!' && c <= '}')
			{
				sprintf(hex_char, "%X", c);
				strncat(hex_str, hex_char, 8);
				i++;
			}
		}

		if (c % 2 == 0 && !mode)
		{
			memset(hex_str, '\0', bits);
			continue;
		}

		mpz_init_set_str(digit_dec_str, hex_str, 16);
		if (!mode) break;

		short prime = mpz_probab_prime_p(digit_dec_str, 10);

		if (prime) break;
		else memset(hex_str, '\0', bits);
	}

	if (base == 10) mpz_get_str(digit, 10, digit_dec_str);
	else strncpy(digit, hex_str, bits);

	fclose(random);
	delete [] hex_str;
	return digit;
}
/* -------------------------==[end: digits generator]==------------------------- */
