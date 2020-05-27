import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    SessionKey sessionKey;
    byte[] decodedIV;
    Cipher c;

    SessionDecrypter(String key, String iv){
        sessionKey = new SessionKey(key);
        decodedIV = Base64.getDecoder().decode(iv);
    }

    SessionDecrypter(byte[] key, byte[] iv){
        sessionKey = new SessionKey(key);
        decodedIV = iv;
    }
    CipherInputStream openCipherInputStream(InputStream input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        c = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(decodedIV);
        c.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
        return new CipherInputStream(input, c);
    }
}
