import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    SessionKey sessionKey;
    Cipher c;
    byte[] counter;
    IvParameterSpec ivParameterSpec;
    SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException{
        sessionKey = new SessionKey(keyLength);
        SecureRandom random = new SecureRandom();
        counter = random.generateSeed(16);
        ivParameterSpec = new IvParameterSpec(counter);
        //counter = ivParameterSpec.getIV();
    }

    SessionEncrypter(byte[] key, byte[] iv){
        sessionKey = new SessionKey(key);
        ivParameterSpec = new IvParameterSpec(iv);
    }

    String encodeKey(){
        return sessionKey.encodeKey();
    }

    String encodeIV(){
        return Base64.getEncoder().encodeToString(counter);
    }

    byte[] getKeyByte(){
        return sessionKey.getSecretKey().getEncoded();
    }

    byte[] getIvByte(){
        return ivParameterSpec.getIV();
    }

    CipherOutputStream openCipherOutputStream(OutputStream output) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException {
        c = Cipher.getInstance("AES/CTR/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
        return new CipherOutputStream(output, c);
    }
}


