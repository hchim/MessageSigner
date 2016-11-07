#include "pkcs7.h"
#include "utils.h"
#include "jni_log.h"

/*PKCS7结构
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {data|signedData|envelopedData|signedAndEnvelopedData|digestedData|encryptedData}
* 	content		#内容由contentType决定
*
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {data}
	content : OCTETSTRING
*
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {signedData}
*	content[optional] : SEQUENCE 							#CERT.RSA是属于signedData类型
*		version : INTEGER
*		digestAlgorithms : SET : DigestAlgorithmIdentifier  #消息摘要的算法
*		contentInfo : SEQUENCE   							#整个文件也是contentInfo结构
*		certificates[optional] : SEQUENCE 					#证书信息
*			tbsCertificate : SEQUENCE #
*				version : INTEGER
*				serialNumber : INTEGER  					#证书的序列号，由证书颁布者和序列号可以唯一确定证书
*				signature ： SEQUENCE : AlgorithmIdentifier
*				issuer : SET 								#证书颁布者
*				validity : SEQUENCE    						#证书的有效期
*				subject : SET #证书主体
*				subjectPublicKeyInfo : SEQUENCE 			#公钥相关信息，包含有加密算法和公钥
*				issuerUniqueID[optional] : BITSTRING
*				subjectUniqueID[optional] : BITSTRING
*				extensions[optional] : SEQUENCE  			#保存有证书扩展信息
*			signatureAlgorithm : AlgorithmIdentifier 		#签名算法 ，如常用的有 SHA256withRSA
*			signatureValue : BITSTRING 						#这是tbsCertificate部分的数字签名信息，防止tbsCertificate内容被修改
*		crls[optional] : SET 								#证书吊销列表
*		signerInfos : SET
			signerInfo : SEQUENCE							#签名者信息
*				version : INTEGER
*				issuerAndSerialNumber : SEQUENCE 			#证书的颁布者和序列号
*				digestAlgorithmId : SEQUENCE : DigestAlgorithmIdentifier #消息摘要的算法
*				authenticatedAttributes[optional]
*				digestEncryptionAlgorithmId : SEQUENCE 			#签名算法
*				encryptedDigest : OCTETSTRING   			#私钥加密后的数据
*				unauthenticatedAttributes[optional]
*
*每项的保存形式为{tag，length，content}
*/

#include "pkcs7.h"

#define TAG "pkcs7"

/**
 * 构造函数，必须提供签名证书文件或者apk文件
 */
pkcs7::pkcs7()
{
    m_content = NULL;
    head = tail = NULL;
    p_cert = p_signer = NULL;
    m_pos = m_length = 0;
}

void pkcs7::set_content(const unsigned char * content, int len)
{
    m_content = (unsigned char *)malloc(sizeof(unsigned char) * m_length);
    memcpy(m_content, content, len);
    m_length = len;
    bool parseResult = parse_pkcs7();
    if (!parseResult) {
        LOGD(TAG, "Failed to parse pkcs7 file\n");
    }
 }

pkcs7::~pkcs7()
{
    element *p = head;
    while (p != NULL) {
        head = p->next;
        free(p);
        p = head;
    }
    free(m_content);
}

/**
 * 根据lenbyte计算出 length所占的字节个数， 1）字节最高位为1，则低7位长度字节数；2）最高位为0，则lenbyte表示长度
 */
int pkcs7::len_num(unsigned char lenbyte)
{
    int num = 1;
    if (lenbyte & 0x80) {
        num += lenbyte & 0x7f;
    }
    return num;
}
/**
 * 将长度信息转化成ASN.1长度格式
 * len <= 0x7f       1
 * len >= 0x80       1 + 非零字节数
 */
int pkcs7::num_from_len(int len)
{
    int num = 0;
    int tmp = len;
    while (tmp) {
        num++;
        tmp >>= 8;
    }
    if ((num == 1 && len >= 0x80) || (num > 1))
        num += 1;
    return num;
}

/**
 *每个element元素都是{tag, length, data}三元组，tag和length分别由tag和len保存，data是由[begin, begin+len)保存。
 *
 *该函数是从data位置计算出到tag位置的偏移值
 */
int pkcs7::tag_offset(element *p)
{
    if (p == NULL)
        return 0;
    int offset = num_from_len(p->len);
    if (m_content[p->begin - offset - 1] == p->tag)
        return offset + 1;
    else
        return 0;
}

/**
 * 根据lenbyte计算长度信息，算法是 lenbyte最高位为1， 则lenbyte & 0x7F表示length的字节长度，后续字节使用大端方式存放
 * 最高位为0， lenbyte直接表示长度
 *
 * 1)若 0x82 0x34 0x45 0x22 ....  0x82是lenbyte， 高位为1，0x82 & 0x7F == 2，则后续两个字节是高端存放的长度信息
    则长度信息为 0x3445
   2)若 lenbyte == 0x34， 最高位为0， 则长度信息是0x34
*/
int pkcs7::get_length(unsigned char lenbyte, int offset)
{
    int len = 0, num;
    unsigned char tmp;
    if (lenbyte & 0x80) {
        num = lenbyte & 0x7f;
        if (num < 0 || num > 4) {
            printf("its too long !\n");
            return 0;
        }
        while (num) {
            len <<= 8;
            tmp = m_content[offset++];
            len += (tmp & 0xff);
            num--;
        }
    } else {
        len = lenbyte & 0xff;
    }
    return len;
}

/**
 *根据名字找到pkcs7中的元素, 若没有找到返回NULL.
 *name: 名字，可以只提供元素名字前面的字符
 *begin: 查找的开始位置
 */
element *pkcs7::get_element(const char *name, element *begin)
{
    if (begin == NULL)
        begin = head;
    element *p = begin;
    while (p != NULL) {
        if (strncmp(p->name, name, strlen(name)) == 0)
            return p;
        p = p->next;
    }
    LOGD(TAG, "not found the \"%s\"\n", name);
    return p;
}

/**
 * 解析证书信息
 */
bool  pkcs7::parse_certificate(int level)
{
    char *names[] = {
            "tbsCertificate",
            "version",
            "serialNumber",
            "signature",
            "issuer",
            "validity",
            "subject",
            "subjectPublicKeyInfo",
            "issuerUniqueID-[optional]",
            "subjectUniqueID-[optional]",
            "extensions-[optional]",
            "signatureAlgorithm",
            "signatureValue" };
    int len = 0;
    unsigned char tag;
    bool have_version = false;
    len = create_element(TAG_SEQUENCE, names[0], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    //version
    tag = m_content[m_pos];
    if (((tag & 0xc0) == 0x80) && ((tag & 0x1f) == 0)) {
        m_pos += 1;
        m_pos += len_num(m_content[m_pos]);
        len = create_element(TAG_INTEGER, names[1], level + 1);
        if (len == -1 || m_pos + len > m_length) {
            return false;
        }
        m_pos += len;
        have_version = true;
    }

    for (int i = 2; i < 11; i++) {
        switch (i) {
            case 2:
                tag = TAG_INTEGER;
                break;
            case 8:
                tag = 0xA1;
                break;
            case 9:
                tag = 0xA2;
                break;
            case 10:
                tag = 0xA3;
                break;
            default:
                tag = TAG_SEQUENCE;
        }
        len = create_element(tag, names[i], level + 1);
        if (i < 8 && len == -1) {
            return false;
        }
        if (len != -1)
            m_pos += len;
    }
    //signatureAlgorithm
    len = create_element(TAG_SEQUENCE, names[11], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //signatureValue
    len = create_element(TAG_BITSTRING, names[12], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    return true;
}

/**
 * 解析签名者信息
 */
bool pkcs7::parse_signerInfo(int level)
{
    char *names[] = {
            "version",
            "issuerAndSerialNumber",
            "digestAlgorithmId",
            "authenticatedAttributes-[optional]",
            "digestEncryptionAlgorithmId",
            "encryptedDigest",
            "unauthenticatedAttributes-[optional]" };
    int len;
    unsigned char tag;
    for (int i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        switch (i) {
            case 0:
                tag = TAG_INTEGER;
                break;
            case 3:
                tag = 0xA0;
                break;
            case 5:
                tag = TAG_OCTETSTRING;
                break;
            case 6:
                tag = 0xA1;
                break;
            default:
                tag = TAG_SEQUENCE;

        }
        len = create_element(tag, names[i], level);
        if (len == -1 || m_pos + len > m_length) {
            if (i == 3 || i == 6)
                continue;
            return false;
        }
        m_pos += len;
    }
    int ret = (m_pos == m_length ? 1 : 0);
    return true;
}

/**
 * 解析 contentType == signedData 的content部分
 */
bool pkcs7::parse_content(int level)
{

    char *names[] = {"version",
                     "DigestAlgorithms",
                     "contentInfo",
                     "certificates-[optional]",
                     "crls-[optional]",
                     "signerInfos",
                     "signerInfo"};

    unsigned char tag;
    int len = 0;
    element *p = NULL;
    //version
    len = create_element(TAG_INTEGER, names[0], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //DigestAlgorithms
    len = create_element(TAG_SET, names[1], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //contentInfo
    len = create_element(TAG_SEQUENCE, names[2], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    m_pos += len;
    //certificates-[optional]
    tag = m_content[m_pos];
    if (tag == TAG_OPTIONAL) {
        m_pos++;
        m_pos += len_num(m_content[m_pos]);
        len = create_element(TAG_SEQUENCE, names[3], level);
        if (len == -1 || m_pos + len > m_length) {
            return false;
        }
        p_cert = tail;
        bool ret = parse_certificate(level + 1);
        if (ret == false) {
            return ret;
        }
    }
    //crls-[optional]
    tag = m_content[m_pos];
    if (tag == 0xA1) {
        m_pos++;
        m_pos += len_num(m_content[m_pos]);
        len = create_element(TAG_SEQUENCE, names[4], level);
        if (len == -1 || m_pos + len > m_length) {
            return false;
        }
        m_pos += len;
    }
    //signerInfos
    tag = m_content[m_pos];
    if (tag != TAG_SET) {
        return false;
    }
    len = create_element(TAG_SET, names[5], level);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    //signerInfo
    len = create_element(TAG_SEQUENCE, names[6], level + 1);
    if (len == -1 || m_pos + len > m_length) {
        return false;
    }
    p_signer = tail;
    return parse_signerInfo(level + 2);
}

/**
 * 创建element.pkcs7中的每个元素都有对应element.
 */
int pkcs7::create_element(unsigned char tag, char *name, int level)
{
    unsigned char get_tag = m_content[m_pos++];
    if (get_tag != tag) {
        m_pos--;
        return -1;
    }
    unsigned char lenbyte = m_content[m_pos];
    int len = get_length(lenbyte, m_pos + 1);
    m_pos += len_num(lenbyte);

    element *node = (element *)malloc(sizeof(element));
    node->tag = get_tag;
    strcpy(node->name, name);
    node->begin = m_pos;
    node->len = len;
    node->level = level;
    node->next = NULL;

    if (head == NULL) {
        head = tail = node;
    } else {
        tail->next = node;
        tail = node;
    }
    return len;
}

/**
 * 解析文件开始函数
 */
bool pkcs7::parse_pkcs7()
{
    unsigned char tag, lenbyte;
    int len = 0;
    int level = 0;
    tag = m_content[m_pos++];
    if (tag != TAG_SEQUENCE) {
        LOGD(TAG, "not found the Tag indicating an ASN.1!\n");
        return false;
    }
    lenbyte = m_content[m_pos];
    len = get_length(lenbyte, m_pos + 1);
    m_pos += len_num(lenbyte);
    if (m_pos + len > m_length){
        LOGD(TAG, "wrong len\n");
        return false;
    }

    //contentType
    len = create_element(TAG_OBJECTID, "contentType", level);
    if (len == -1) {
        LOGD(TAG, "not found the ContentType!\n");
        return false;
    }
    m_pos += len;
    //optional
    tag = m_content[m_pos++];
    lenbyte = m_content[m_pos];
    m_pos += len_num(lenbyte);
    //content-[optional]
    len = create_element(TAG_SEQUENCE, "content-[optional]", level);
    if (len == -1) {
        LOGD(TAG, "not found the content!\n");
        return false;
    }
    return parse_content(level + 1);
}

/**
 * 获取证书信息的SHA256
 */
char *pkcs7::get_SHA256()
{
    if (p_cert == NULL) {
        LOGD(TAG, "p_cert is null\n");
        return NULL;
    }
    static char ret_sha256[65]; //静态字符数组，被放入在全局数据区，只申请一次，不用担心内存泄露
    int offset = tag_offset(p_cert);
    if (offset == 0) {
        LOGD(TAG, "get offset error!\n");
        return NULL;
    }

    SHA256_digest((const char*) (m_content + p_cert->begin - offset), p_cert->len + offset, ret_sha256);

    return ret_sha256;
}
