import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    public static String serverHost = "localhost";
    public static int serverPort = 4412;

    /* The final destination */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;
    public X509Certificate clientCert;
    public X509Certificate serverCert;
    public byte[] sessionKey;
    public byte[] sessionIV;
    public String flag;

    public void sendHello(String messageType, String Certificate, Socket socket) throws CertificateException, IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", messageType);
        if(messageType.equals("ClientHello")){
            flag = "Client";
            clientCert = VerifyCertificate.getCertificate(Certificate);
            handshakeMessage.putParameter("Certificate", VerifyCertificate.encodeCertificate(clientCert));
        }
        else{
            flag = "Server";
            serverCert = VerifyCertificate.getCertificate(Certificate);
            handshakeMessage.putParameter("Certificate", VerifyCertificate.encodeCertificate(serverCert));
        }
        handshakeMessage.send(socket);
        Logger.log(messageType + " hello send succeeded.");
    }

    public void verifyHello(String CAcert, Socket socket) throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.recv(socket);
        if(handshakeMessage.getParameter("MessageType").equals("ClientHello")){
            flag = "Server";
            try{
                VerifyCertificate.Verify(CAcert, handshakeMessage.getParameter("Certificate"));
                clientCert = VerifyCertificate.decodeCertificate(handshakeMessage.getParameter("Certificate"));
                Logger.log(flag + " verify succeeded.");
            }catch (Exception e){
                Logger.log(flag + " verify failed.");
                socket.close();
            }
        }
        else if(handshakeMessage.getParameter("MessageType").equals("ServerHello")){
            try{
                VerifyCertificate.Verify(CAcert, handshakeMessage.getParameter("Certificate"));
                serverCert = VerifyCertificate.decodeCertificate(handshakeMessage.getParameter("Certificate"));
                Logger.log(flag + "verify succeeded.");
            }catch (Exception e){
                Logger.log(flag + "verify failed.");
                socket.close();
            }
        }
        else{
            Logger.log("Message type error.");
            socket.close();
        }
    }

    public void clientForward(String messgaeType, String host, String port, Socket socket) throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", messgaeType);
        handshakeMessage.putParameter("TargetHost", host);
        handshakeMessage.putParameter("TargetPort", port);
        handshakeMessage.send(socket);
        Logger.log("Client forward succeeded.");
    }

    public void forwardVerify(Socket socket) throws IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.recv(socket);
        if(handshakeMessage.getParameter("MessageType").equals("Forward")){
            targetHost = handshakeMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(handshakeMessage.getParameter("TargetPort"));
            Logger.log("Server forward verify succeed.");
        }
        else{
            Logger.log("Forward message type error.");
            socket.close();
        }
    }

    public void session(String messageType, String sessionHost, String sessionPort, Socket socket) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IOException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.putParameter("MessageType", messageType);
        SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
        PublicKey publicKey = clientCert.getPublicKey();
        sessionKey = sessionEncrypter.getKeyByte();
        sessionIV = sessionEncrypter.getIvByte();
        byte[] encryptedKey = HandshakeCrypto.encrypt(sessionKey, publicKey);
        byte[] encryptedIV = HandshakeCrypto.encrypt(sessionIV, publicKey);
        handshakeMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedKey));
        handshakeMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIV));
        handshakeMessage.putParameter("SessionHost", sessionHost);
        handshakeMessage.putParameter("SessionPort", sessionPort);
        handshakeMessage.send(socket);
        Logger.log("Session created.");
        Logger.log("Server handshake finished.");
    }

    public void receiveSession(Socket socket, String key) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        handshakeMessage.recv(socket);
        if(handshakeMessage.getParameter("MessageType").equals("Session")){
            PrivateKey privateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(key);
            sessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(handshakeMessage.getParameter("SessionKey")), privateKey);
            sessionIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(handshakeMessage.getParameter("SessionIV")), privateKey);
            serverHost = handshakeMessage.getParameter("SessionHost");
            serverPort = Integer.parseInt(handshakeMessage.getParameter("SessionPort"));
            Logger.log("Session message received.");
            Logger.log("Client handshake finished.");
        }
        else{
            Logger.log("Session message type error.");
            socket.close();
        }
    }

    public byte[] getSessionKey(){
        return sessionKey;
    }

    public byte[] getSessionIV(){
        return sessionIV;
    }
}
