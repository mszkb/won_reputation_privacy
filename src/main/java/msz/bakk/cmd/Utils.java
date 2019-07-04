package msz.bakk.cmd;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class Utils {
    public static String generateRandomHash() throws NoSuchAlgorithmException {
        SecureRandom rnd = new SecureRandom();
        String randomNumber = String.valueOf(rnd.nextInt(10000));

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(
                randomNumber.getBytes(StandardCharsets.UTF_8));
        String hashedRandomNumber = new String(Hex.encode(hash));

        return hashedRandomNumber;
    }
}
