package msz.Utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAUtils {
    private static int keyLength = 4096;

    public static AsymmetricCipherKeyPair generateKeyPair() {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
                new BigInteger("10001", 16), new SecureRandom(), keyLength,
                80));
        return generator.generateKeyPair();
    }

    public static void setKeyLength(int newLength) {
        if (newLength < 0 || newLength >= Integer.MAX_VALUE) {
            return;
        }

        keyLength = newLength;
    }
}
