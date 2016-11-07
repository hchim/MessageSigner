#ifndef MESSAGESIGNER_PKCS7_H
#define MESSAGESIGNER_PKCS7_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zip.h>

#define TAG_INTEGER 	0x02
#define TAG_BITSTRING	0x03
#define TAG_OCTETSTRING 0x04
#define TAG_OBJECTID	0x06
#define TAG_UTCTIME		0x17
#define TAG_GENERALIZEDTIME 0x18
#define TAG_SEQUENCE	0x30
#define TAG_SET			0x31
#define TAG_OPTIONAL	0xA0

#define NAME_LEN 	63

typedef struct element {
    unsigned char tag;
    char name[NAME_LEN];
    int begin;
    int len;
    int level;
    struct element *next;
}element;

class pkcs7 {
public:
    pkcs7();
    ~pkcs7();
    void set_content(const unsigned char * content, int len);
    char* get_SHA256();

private:
    int  len_num(unsigned char lenbyte);
    int  num_from_len(int len);
    int  tag_offset(element *p);

    int  get_length(unsigned char lenbyte, int pos);

    element *get_element(const char *name, element *begin);
    int create_element(unsigned char tag, char *name, int level);

    bool parse_content(int level);
    bool parse_pkcs7();
    bool parse_certificate(int level);
    bool parse_signerInfo(int level);

private:
    unsigned char *	m_content;
    int 			m_length;
    int 			m_pos;
    struct element *head;
    struct element *tail;
    struct element *p_cert;
    struct element *p_signer;
};

#endif //MESSAGESIGNER_PKCS7_H
