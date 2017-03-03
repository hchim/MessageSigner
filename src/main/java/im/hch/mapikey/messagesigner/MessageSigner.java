package im.hch.mapikey.messagesigner;

import android.net.Uri;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class MessageSigner {
    private static final String LIB_NAME = "msigner";
    static {
        System.loadLibrary(LIB_NAME);
    }

    private static MessageSigner instance = null;

    public static synchronized MessageSigner getInstance() {
        if (instance == null) {
            instance = new MessageSigner();
        }

        return instance;
    }

    private MessageSigner() {
        nativeInit();
    }

    /**
     * Generate the signature for the request.
     * @param method
     * @param url
     * @param body
     * @param headers
     * @return
     */
    public String generateSignature(String method, String url, String body, Map<String, String> headers) {
        String digest = requestDigest(method, url, body, headers);
        if (digest == null) {
            return null;
        }

        return nativeSignMessage(digest);
    }

    /**
     * Generate the SHA256 digest of the request.
     * @param method
     * @param url
     * @param body
     * @param headers
     * @return
     */
    private String requestDigest(String method, String url, String body, Map<String, String> headers) {
        StringBuffer buffer = new StringBuffer();
        buffer.append(method);
        buffer.append(getUri(url));

        if (body != null) {
            buffer.append(body);
        }

        if (headers != null && headers.size() > 0) {
            List<String> list = new ArrayList();
            list.addAll(headers.keySet());
            Collections.sort(list);

            for (String key : list) {
                buffer.append(key);
                buffer.append(headers.get(key));
            }
        }

        return HashUtils.generateSHA256Hash(buffer.toString());
    }

    private String getUri(String url) {
        if (url.startsWith("http")) {
            Uri uri = Uri.parse(url);
            return uri.getPath();
        }
        return url;
    }

    public String signMessage(String message) {
        if (message == null) {
            return null;
        }

        return nativeSignMessage(message);
    }

    public String encodeMessage(String message) {
        return Base64.encodeToString(message.getBytes(), Base64.DEFAULT);
    }

    public String decodeMessage(String message) {
        byte[] decoded = Base64.decode(message.getBytes(), Base64.DEFAULT);
        try {
            return new String(decoded, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return "";
        }
    }

    /**
     * A native method that is implemented by the 'messagesigner-lib' native library,
     * which checks the api key and sign the message with the apikey.
     */
    private native String nativeSignMessage(String message);

    /**
     * Native init the library.
     */
    private native void nativeInit();
}
