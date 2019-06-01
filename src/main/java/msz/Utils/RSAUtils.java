package msz.Utils;

import msz.Message.Certificate;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

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

    public static byte[] signString(KeyPair keyPair, String string) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureOfRandomHash = Signature.getInstance("SHA256withECDSA");
        signatureOfRandomHash.initSign(keyPair.getPrivate());
        signatureOfRandomHash.update(string.getBytes(StandardCharsets.UTF_8));
        return signatureOfRandomHash.sign();
    }

    public static byte[] signString(PrivateKey privateKey, String string) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureOfRandomHash = Signature.getInstance("SHA256withECDSA");
        signatureOfRandomHash.initSign(privateKey);
        signatureOfRandomHash.update(string.getBytes(StandardCharsets.UTF_8));
        return signatureOfRandomHash.sign();
    }

    public static boolean verifySignature(byte[] signedRandomHash, String original, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        boolean isHashCorrect;

        Signature verifySignature = Signature.getInstance("SHA256withECDSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(original.getBytes(StandardCharsets.UTF_8));
        isHashCorrect = verifySignature.verify(signedRandomHash);

        return isHashCorrect;
    }

    public static boolean verifyCertificate(byte[] certToVerify, byte[] certSignatureToVerify, PublicKey publicKey) throws SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        Signature certificateTextSignature = Signature.getInstance("SHA256withECDSA", "SunEC");
        certificateTextSignature.initVerify(publicKey);
        certificateTextSignature.update(certToVerify);

        return certificateTextSignature.verify(certSignatureToVerify);
    }
}
