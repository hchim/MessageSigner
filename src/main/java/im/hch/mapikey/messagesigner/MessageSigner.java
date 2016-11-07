package im.hch.mapikey.messagesigner;

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
