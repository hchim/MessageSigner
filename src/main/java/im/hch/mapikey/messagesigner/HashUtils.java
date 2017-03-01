package im.hch.mapikey.messagesigner;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by huiche on 2/28/17.
 */

public class HashUtils {
    public static final String TAG = "HashUtils";
    public static final String SHA256_ALGORITHM = "SHA-256";

    public static String generateSHA256Hash(String str) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA256_ALGORITHM);
            byte[] signature = digest.digest(str.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();

            for (int i = 0; i < signature.length; i++) {
                String hex = Integer.toHexString(0xff & signature[i]);
                if(hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, e.getMessage(), e);
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, e.getMessage(), e);
        }
        return null;
    }
}
