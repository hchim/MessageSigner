#ifndef MESSAGESIGNER_PACKAGE_UTILS_H
#define MESSAGESIGNER_PACKAGE_UTILS_H

#define MAX_PACKAGE_NAME_LEN 256

/*
 * Get the package name of the process that invoking this method.
 */
int get_package_name(char * package_name);

/*
 * Get the apk file path of the specified package name.
 * The apk file of the package are saved in the /data/app/ dir.
 */
int get_apk_file_path(char* package_name, char* apk_path);

/*
 * Search the apk file and find out the name of the certificate file.
 */
int get_certificate_file(char* apk_path, char* cert_file);

/*
 * Read all the data of the specified file from the APK file.
 */
int read_file_from_apk(char* apk_path, char* filename, uint8_t ** read_buf);

#endif //MESSAGESIGNER_PACKAGE_UTILS_H
