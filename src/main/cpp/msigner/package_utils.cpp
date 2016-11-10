#include <stdio.h>
#include <unistd.h>
#include <fstream>
#include <zip.h>

#include "package_utils.h"
#include "jni_log.h"
#include "string_extra.h"

using std::ifstream;
using std::size_t;

#define TAG "package_utils"

zip* apk_file = NULL;

int get_package_name(char * package_name) {
    int pid = getpid();
    char filename[128] = {0};
    int len = snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
    if (len < 0) {
        LOGD(TAG, "Failed to create cmdline filename for pid: %d\n", pid);
        return 0;
    }

    ifstream ifs(filename);
    if (!ifs.is_open() || ifs.fail()) {
        LOGD(TAG, "Failed to open cmdline file: %s\n", filename);
        return 0;
    }

    ifs.getline(package_name, MAX_PACKAGE_NAME_LEN);
    ifs.close();

    return 1;
}

int get_apk_file_path(char* package_name, char* apk_path) {
    char path_prefix[512] = {0};

    int len = snprintf(path_prefix, sizeof(path_prefix), "/data/app/%s", package_name);
    if (len < 0) {
        LOGD(TAG, "Failed to create path prefix: %s\n", path_prefix);
        return 0;
    }

    ifstream ifs("/proc/self/maps");
    if (!ifs.is_open()) {
        LOGD(TAG, "Failed to open maps file");
        return 0;
    }

    char line[1024] = {0};
    while(ifs) {
        ifs.getline(line, sizeof(line));
        char* p = strstr(line, path_prefix);
        if (p != NULL && ends_with(line, ".apk")) {
            strncpy(apk_path, p, strlen(p));
            break;
        }
    }

    ifs.close();

    return 1;
}

int get_certificate_file(char* apk_path, char* cert_file) {
    if (apk_file == NULL) {
        apk_file = zip_open(apk_path, 0, NULL);
    }

    if (apk_file == NULL) {
        LOGD(TAG, "Failed to open apk file at path: %s\n", apk_path)
        return 0;
    }

    int num = zip_get_num_files(apk_file);
    for (int i = 0; i < num; i++) {
        const char* name = zip_get_name(apk_file, i, 0);
        if (name == NULL) {
            LOGD(TAG, "Failed to read zip file name at index %i : %s", i, zip_strerror(apk_file));
            return 0;
        }

        if (strstr(name, "META-INF/") == name // starts with META-INF/
            && ends_with(name, ".RSA")) {
            strncpy(cert_file, name, strlen(name));
            return 1;
        }
    }

    return 0;
}

int read_file_from_apk(char* apk_path, char* filename, uint8_t ** read_buf) {
    if (apk_file == NULL) {
        apk_file = zip_open(apk_path, 0, NULL);
    }

    if (apk_file == NULL) {
        LOGD(TAG, "Failed to open apk file.\n")
        return -1;
    }

    struct zip_stat fstat;
    struct zip_file* file = zip_fopen(apk_file, filename, 0);

    if (file != NULL) {
        if (zip_stat(apk_file, filename, 0, &fstat) != 0) {
            LOGD(TAG, "Failed to get file information: %s\n", filename);
            return -1;
        }
    } else {
        LOGD(TAG, "Failed to open zip file: %s\n", filename);
        return -1;
    }
    *read_buf = (uint8_t *) malloc(fstat.size + 1);

    if (*read_buf == NULL) {
        LOGE(TAG, "Failed to allocate memory");
        return -1;
    }

    int num = zip_fread(file, *read_buf, fstat.size);
    zip_fclose(file);

    return num;
}