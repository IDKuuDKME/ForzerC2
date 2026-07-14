#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <urlmon.h>
#include <winreg.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "urlmon.lib")

#define FORZER_REG_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define FORZER_REG_VALUE "Forzer"

/* Default location of the latest Forzer.exe (your own repo).
   Override at runtime with FORZER_UPDATE_URL if you ever need to. */
#ifndef FORZER_UPDATE_URL
#define FORZER_UPDATE_URL \
    "https://raw.githubusercontent.com/Peter211231231231232131/NotSoSafe/master/Forzer.exe"
#endif

static int set_startup(int enable) {
    char self_path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        fprintf(stderr, "error: GetModuleFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    HKEY key;
    LONG r = RegOpenKeyExA(HKEY_CURRENT_USER, FORZER_REG_KEY, 0,
                           KEY_SET_VALUE, &key);
    if (r != ERROR_SUCCESS) {
        fprintf(stderr, "error: cannot open Run key (%ld)\n", r);
        return 1;
    }

    if (enable) {
        r = RegSetValueExA(key, FORZER_REG_VALUE, 0, REG_SZ,
                           (const BYTE *)self_path,
                           (DWORD)(strlen(self_path) + 1));
        RegCloseKey(key);
        if (r != ERROR_SUCCESS) {
            fprintf(stderr, "error: could not add startup entry (%ld)\n", r);
            return 1;
        }
        printf("Forzer will run at user logon: %s\n", self_path);
    } else {
        r = RegDeleteValueA(key, FORZER_REG_VALUE);
        RegCloseKey(key);
        if (r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND) {
            printf("Forzer removed from startup.\n");
        } else {
            fprintf(stderr, "error: could not remove startup entry (%ld)\n", r);
            return 1;
        }
    }
    return 0;
}

static int do_update(void) {
    char self_path[MAX_PATH];
    char tmp_path[MAX_PATH];
    char bak_path[MAX_PATH];

    if (!GetModuleFileNameA(NULL, self_path, MAX_PATH)) {
        fprintf(stderr, "error: GetModuleFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    const char *url = getenv("FORZER_UPDATE_URL");
    if (!url || !*url) {
        url = FORZER_UPDATE_URL;
    }

    if (!GetTempFileNameA(self_path, "frz", 0, tmp_path)) {
        fprintf(stderr, "error: GetTempFileName failed (%lu)\n", GetLastError());
        return 1;
    }

    printf("downloading update from %s\n", url);
    HRESULT hr = URLDownloadToFileA(NULL, url, tmp_path, 0, NULL);
    if (FAILED(hr)) {
        fprintf(stderr, "error: download failed (hr=0x%lx)\n", hr);
        DeleteFileA(tmp_path);
        return 1;
    }

    snprintf(bak_path, MAX_PATH, "%s.bak", self_path);
    DeleteFileA(bak_path);
    if (!MoveFileExA(self_path, bak_path, MOVEFILE_REPLACE_EXISTING)) {
        fprintf(stderr, "error: could not rename current exe (%lu)\n", GetLastError());
        DeleteFileA(tmp_path);
        return 1;
    }

    if (!MoveFileExA(tmp_path, self_path, MOVEFILE_REPLACE_EXISTING)) {
        fprintf(stderr, "error: could not install update (%lu)\n", GetLastError());
        MoveFileExA(bak_path, self_path, MOVEFILE_REPLACE_EXISTING);
        DeleteFileA(tmp_path);
        return 1;
    }

    printf("update installed: %s\n", self_path);
    printf("previous version kept as: %s\n", bak_path);
    return 0;
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--update") == 0) {
            return do_update();
        }
        if (strcmp(argv[i], "--install-startup") == 0) {
            return set_startup(1);
        }
        if (strcmp(argv[i], "--remove-startup") == 0) {
            return set_startup(0);
        }
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            printf("Forzer 1.0.0\n");
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: Forzer.exe [--update] [--version] [--help]\n");
            printf("  --update            download and replace this executable\n");
            printf("                      (from FORZER_UPDATE_URL)\n");
            printf("  --install-startup   run Forzer automatically at user logon\n");
            printf("  --remove-startup    stop running Forzer at user logon\n");
            return 0;
        }
    }
    printf("Forzer. Run with --update to self-update.\n");
    return 0;
}
