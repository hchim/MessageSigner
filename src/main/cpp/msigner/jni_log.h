#ifndef MESSAGESIGNER_JNI_LOG_H
#define MESSAGESIGNER_JNI_LOG_H

#include <android/log.h>

#define LOGE(TAG, format, ...)   __android_log_print(ANDROID_LOG_ERROR, TAG, format, ##__VA_ARGS__);
#define LOGD(TAG, format, ...)   __android_log_print(ANDROID_LOG_DEBUG, TAG, format, ##__VA_ARGS__);
#define LOGI(TAG, format, ...)   __android_log_print(ANDROID_LOG_INFO, TAG, format, ##__VA_ARGS__);

#endif //MESSAGESIGNER_JNI_LOG_H
