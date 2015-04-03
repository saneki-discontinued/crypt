#include <crypt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#define CRYPT_ID_MD5 "1"
#define CRYPT_ID_SHA256 "5"
#define CRYPT_ID_SHA512 "6"

// Leaving out blowfish, only available in some linux distributions
// according to crypt(3) man page
// #define CRYPT_ID_BLOWFISH "2a"

typedef struct __crypt_args_t
{
	const char *pass;
	const char *salt;
	const char *id;
	bool no_newline;
	bool help;
} crypt_args_t;

#define CRYPT_ARGS_DEFAULT { NULL, NULL, CRYPT_ID_SHA512, false, false }

void parse_args(int argc, char *argv[], crypt_args_t *cargs);
void print_help();

int main(int argc, char *argv[])
{
	crypt_args_t cargs = CRYPT_ARGS_DEFAULT;
	parse_args(argc, argv, &cargs);

	// Todo: A lot of stuff

	if(cargs.help)
	{
		print_help();
		return 0;
	}

	if(cargs.pass == NULL)
	{
		fprintf(stderr, "nothing to hash, aborting\n");
		return 1;
	}

	if(cargs.salt == NULL || strlen(cargs.salt) == 0)
	{
		fprintf(stderr, "a salt is required, aborting\n");
		return 1;
	}

	char *hashed;

	if(cargs.id == NULL)
	{
		hashed = crypt(cargs.pass, cargs.salt);
	}
	else
	{
		const char *id = cargs.id;

		size_t full_len = strlen(cargs.salt) + strlen(id) + 3;
		char full_salt[full_len + 1];
		sprintf(full_salt, "$%s$%s$", id, cargs.salt);

		hashed = crypt(cargs.pass, full_salt);
	}

	// Print hashed password
	if(cargs.no_newline) printf("%s", hashed);
	else                 printf("%s\n", hashed);

	return 0;
}

void parse_args(int argc, char *argv[], crypt_args_t *cargs)
{
	const char *argstr = "156Ins:h?";
	extern char *optarg;
	int option_index = 0;
	int c;

	struct option long_options[] =
	{
		{ "md5", no_argument,         0, '1' },
		{ "no-id", no_argument,       0, 'I' },
		{ "no-newline", no_argument,  0, 'n' },
		{ "salt",  required_argument, 0, 's' },
		{ "sha256", no_argument,      0, '5' },
		{ "sha512", no_argument,      0, '6' },
		{ "help",  no_argument,       0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while((c = getopt_long(argc, argv, argstr, long_options, &option_index)) != -1)
	{
		switch(c)
		{
			case '1':
				cargs->id = CRYPT_ID_MD5;
				break;

			case '5':
				cargs->id = CRYPT_ID_SHA256;
				break;

			case '6':
				cargs->id = CRYPT_ID_SHA512;
				break;

			case 'I':
				cargs->id = NULL;
				break;

			case 'n':
				cargs->no_newline = true;
				break;

			case 's':
				cargs->salt = optarg;
				break;

			case '?':
			case 'h':
				cargs->help = true;
				break;
		}
	}

	// Last argument should be password, or string to hash
	for(int i = optind; i < argc; i++)
	{
		cargs->pass = argv[i];
	}
}

void print_help()
{
	printf("Usage: crypt [options] [-s salt] password\n");
	printf("\n");
	printf("Options:\n");
	printf("  -1, --md5          use crypt(3) MD5 salt id\n");
	printf("  -5, --sha256       use crypt(3) SHA256 salt id\n");
	printf("  -6, --sha512       use crypt(3) SHA512 salt id (default)\n");
	printf("  -I, --no-id        don't use a salt id\n");
	printf("  -n, --no-newline   don't print a newline after the hash\n");
	printf("  -s, --salt         specify salt to use\n");
	printf("  -h, -?, --help     output this message\n");
	printf("\n");
}
