package msz.bakk.protocol.Utils;

import java.security.SecureRandom;

/**
 * The RNG-factor is the best, especially when we want drops from bosses and random crits
 */
public class RNG {
    private static int bound = 10000;

    public static byte[] generateRNGBytes() {
        byte[] bytes = new byte[bound];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
