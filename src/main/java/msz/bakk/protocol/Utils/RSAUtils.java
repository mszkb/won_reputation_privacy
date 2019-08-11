package msz.bakk.protocol.Utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class RSAUtils {
    private static int keyLength = 2048;

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
        return signString(keyPair.getPrivate(), string);
    }

    public static byte[] signBlindedString(AsymmetricKeyParameter privateKey, byte[] blinded) {
        RSAEngine signerEngine = new RSAEngine();
        signerEngine.init(true, privateKey);
        return signerEngine.processBlock(blinded, 0, blinded.length);
    }

    public static byte[] signString(PrivateKey privateKey, String string) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return signString(privateKey, string.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] signString(PrivateKey privateKey, byte[] byteString) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureOfRandomHash = Signature.getInstance("SHA256withECDSA");
        signatureOfRandomHash.initSign(privateKey);
        signatureOfRandomHash.update(byteString);
        return signatureOfRandomHash.sign();
    }

    public static boolean verifySignature(byte[] signature, String original, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return verifySignature(signature, original.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    public static boolean verifySignature(byte[] signature, byte[] original, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        boolean isHashCorrect;

        Signature verifySignature = Signature.getInstance("SHA256withECDSA");
        verifySignature.initVerify(publicKey);
        verifySignature.update(original);
        isHashCorrect = verifySignature.verify(signature);

        return isHashCorrect;
    }

    public static boolean verifyCertificate(byte[] certToVerify, byte[] certSignatureToVerify, PublicKey publicKey) throws SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        Signature certificateTextSignature = Signature.getInstance("SHA256withECDSA", "SunEC");
        certificateTextSignature.initVerify(publicKey);
        certificateTextSignature.update(certToVerify);

        return certificateTextSignature.verify(certSignatureToVerify);
    }
}
