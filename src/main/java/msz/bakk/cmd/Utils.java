package msz.bakk.cmd;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


public class Utils {
    public static String generateRandomHash() throws NoSuchAlgorithmException {
        String randomNumber = Utils.generateRandomNumber();
        return Utils.generateHash(randomNumber);
    }

    public static String generateHash(String random) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(
                random.getBytes(StandardCharsets.UTF_8));
        String hashedRandomNumber = new String(Hex.encode(hash));

        return hashedRandomNumber;
    }

    public static String generateRandomNumber () {
        SecureRandom rnd = new SecureRandom();
        return String.valueOf(rnd.nextInt(10000));
    }
}
