#include <crypt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

const char *g_crypt_id_md5 = "1";
const char *g_crypt_id_blowfist = "2a";
const char *g_crypt_id_sha256 = "5";
const char *g_crypt_id_sha512 = "6";

typedef struct __crypt_args_t
{
	const char *pass;
	const char *salt;
	bool no_id;
	bool no_newline;
	bool help;
} crypt_args_t;

#define CRYPT_ARGS_DEFAULT { NULL, NULL, false, false, false }

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

	if(cargs.salt == NULL)
	{
		fprintf(stderr, "a salt is currently required, aborting\n");
		return 1;
	}

	// Force SHA512 for now
	const char *id = g_crypt_id_sha512;

	int salt_len = strlen(cargs.salt);
	int salt_id_len = strlen(id);

	// Todo: Positive checks

	size_t full_len = (size_t)salt_len + (size_t)salt_id_len + 3;
	char full_salt[full_len + 1];
	sprintf(full_salt, "$%s$%s$", id, cargs.salt);

	char *hashed = crypt(cargs.pass, full_salt);

	// Print hashed password
	if(cargs.no_newline) printf("%s", hashed);
	else                 printf("%s\n", hashed);

	return 0;
}

void parse_args(int argc, char *argv[], crypt_args_t *cargs)
{
	const char *argstr = "Ins:h?";
	extern char *optarg;
	int option_index = 0;
	int c;

	struct option long_options[] =
	{
		{ "no-id", no_argument,       0, 'I' },
		{ "no-newline", no_argument,  0, 'n' },
		{ "salt",  required_argument, 0, 's' },
		{ "help",  no_argument,       0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while((c = getopt_long(argc, argv, argstr, long_options, &option_index)) != -1)
	{
		switch(c)
		{
			case 'I':
				cargs->no_id = true;
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
	printf("  -I, --no-id        don't use a salt id (not yet implemented)\n");
	printf("  -n, --no-newline   don't print a newline after the hash\n");
	printf("  -s, --salt         specify salt to use\n");
	printf("  -h, -?, --help     output this message\n");
	printf("\n");
}
