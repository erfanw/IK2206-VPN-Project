import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class SessionKey
{
    SecretKey secret;
    SessionKey(Integer keyLength) throws NoSuchAlgorithmException {
        KeyGenerator key = KeyGenerator.getInstance("AES");
        key.init(keyLength);
        secret = key.generateKey();
    }

    SessionKey(String encodedKey){
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        secret = new SecretKeySpec(decodedKey,"AES");
    }

   SessionKey(byte[] key){
        secret = new SecretKeySpec(key, "AES");
    }

    SecretKey getSecretKey(){
        return secret;
    }

    String encodeKey(){
        byte[] keyByte= secret.getEncoded();
        return Base64.getEncoder().encodeToString(keyByte);
    }
}