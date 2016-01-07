#include <crypt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#define CRYPT_VERSION "1.0.0"

#define CRYPT_ID_MD5 "1"
#define CRYPT_ID_SHA256 "5"
#define CRYPT_ID_SHA512 "6"

// Leaving out blowfish, only available in some linux distributions
// according to crypt(3) man page
// #define CRYPT_ID_BLOWFISH "2a"

const char *g_pass = NULL;
const char *g_salt = NULL;
const char *g_id = CRYPT_ID_SHA512;
bool g_no_newline = false;
bool g_version = false;
bool g_help = false;

void parse_args(int argc, char *argv[])
{
	const char *argstr = "156Ins:vh?";
	extern char *optarg;
	int option_index = 0;
	int c;

	struct option long_options[] = {
		{ "md5", no_argument,         0, '1' },
		{ "no-id", no_argument,       0, 'I' },
		{ "no-newline", no_argument,  0, 'n' },
		{ "salt",  required_argument, 0, 's' },
		{ "sha256", no_argument,      0, '5' },
		{ "sha512", no_argument,      0, '6' },
		{ "version", no_argument,     0, 'v' },
		{ "help",  no_argument,       0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((c = getopt_long(argc, argv, argstr, long_options, &option_index)) != -1) {
		switch (c) {
			case '1':
				g_id = CRYPT_ID_MD5;
				break;
			case '5':
				g_id = CRYPT_ID_SHA256;
				break;
			case '6':
				g_id = CRYPT_ID_SHA512;
				break;
			case 'I':
				g_id = NULL;
				break;
			case 'n':
				g_no_newline = true;
				break;
			case 's':
				g_salt = optarg;
				break;
			case 'v':
				g_version = true;
				break;
			case '?':
			case 'h':
				g_help = true;
				break;
		}
	}

	// Last argument should be password, or string to hash
	for (int i = optind; i < argc; i++) {
		g_pass = argv[i];
	}
}

void print_version()
{
	printf("crypt version %s\n", CRYPT_VERSION);
}

void print_help()
{
	print_version();
	printf("Usage: crypt [options] [-s salt] password\n");
	printf("\n");
	printf("Options:\n");
	printf("  -1, --md5          use crypt(3) MD5 salt id\n");
	printf("  -5, --sha256       use crypt(3) SHA256 salt id\n");
	printf("  -6, --sha512       use crypt(3) SHA512 salt id (default)\n");
	printf("  -I, --no-id        don't use a salt id\n");
	printf("  -n, --no-newline   don't print a newline after the hash\n");
	printf("  -s, --salt         specify salt to use\n");
	printf("  -v, --version      output the version\n");
	printf("  -h, -?, --help     output this message\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	parse_args(argc, argv);

	if (g_help) {
		print_help();
		return 0;
	} else if (g_version) {
		print_version();
		return 0;
	}

	if (g_pass == NULL) {
		fprintf(stderr, "nothing to hash, aborting\n");
		return 1;
	}

	if (g_salt == NULL || strlen(g_salt) == 0) {
		fprintf(stderr, "a salt is required, aborting\n");
		return 1;
	}

	char *hashed;

	if (g_id == NULL) {
		hashed = crypt(g_pass, g_salt);
	} else {
		const char *id = g_id;

		size_t full_len = strlen(g_salt) + strlen(id) + 3;
		char full_salt[full_len + 1];
		sprintf(full_salt, "$%s$%s$", id, g_salt);

		hashed = crypt(g_pass, full_salt);
	}

	if (hashed == NULL) {
		fprintf(stderr, "crypt(3) returned NULL, aborting\n");
		return 1;
	}

	// Print hashed password
	if (g_no_newline)
		printf("%s", hashed);
	else
		printf("%s\n", hashed);

	return 0;
}
