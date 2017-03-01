package im.hch.mapikey.messagesigner;

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
        buffer.append(url);

        if (body != null) {
            buffer.append(body);
        }

        if (headers != null && headers.size() > 0) {
            for (String key : headers.keySet()) {
                buffer.append(key);
                buffer.append(headers.get(key));
            }
        }

        return HashUtils.generateSHA256Hash(buffer.toString());
    }

    public String signMessage(String message) {
        if (message == null) {
            return null;
        }

        return nativeSignMessage(message);
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
