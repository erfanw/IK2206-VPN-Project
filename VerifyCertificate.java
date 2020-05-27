import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class VerifyCertificate {
    public static void Verify(String caFileName, String userFile) throws FileNotFoundException, CertificateException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        X509Certificate caCert = getCertificate(caFileName);
        X509Certificate userCert = decodeCertificate(userFile);
        caCert.verify(caCert.getPublicKey());
        userCert.verify(caCert.getPublicKey());
    }

    public static X509Certificate getCertificate(String fileName) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream file = new FileInputStream(fileName);
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(file);
        return cert;
    }

    public static X509Certificate decodeCertificate(String certString) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        byte[] certByte = Base64.getDecoder().decode(certString);
        InputStream inputStream = new ByteArrayInputStream(certByte);
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inputStream);
        return cert;
    }

    public static String encodeCertificate(X509Certificate cert) throws CertificateEncodingException {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

}


