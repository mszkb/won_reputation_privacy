package msz.bakk.protocol.Utils;

import msz.bakk.protocol.Message.Reputationtoken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * This class creates blind signatures and verifies them.
 *
 * @source: https://www.programcreek.com/java-api-examples/?code=nmldiegues/easy-vote/easy-vote-master/SIRSFramework/src/sirs/framework/criptography/CriptoUtils.java
 *          https://gist.github.com/mjethani/e6d8b3e458ff59ef5b6e
 */
public class BlindSignatureUtils {
    private static final Log LOG = LogFactory.getLog(BlindSignatureUtils.class);

    private final RSABlindingParameters blindingParameters;
    private final int saltL = 10;
    private final AsymmetricKeyParameter privateKey;
    private final AsymmetricKeyParameter publicKey;
    private RSABlindingEngine rsaBlindedEngine;
    private PSSSigner blindSigner;

    /**
     * Generate private and public key
     * Initialize the RSABlindingFactor of Bouncycastle
     */
    public BlindSignatureUtils() {
        AsymmetricCipherKeyPair keys = RSAUtils.generateKeyPair();
        this.publicKey = keys.getPublic();
        this.privateKey = keys.getPrivate();

        RSABlindingFactorGenerator rsaBlindingFactorGenerator = new RSABlindingFactorGenerator();
        rsaBlindingFactorGenerator.init(publicKey);
        BigInteger blindingFactor = rsaBlindingFactorGenerator.generateBlindingFactor();

        this.blindingParameters = new RSABlindingParameters((RSAKeyParameters) publicKey, blindingFactor);
    }

    public BlindSignatureUtils(RSAKeyParameters publicKey) {
        AsymmetricCipherKeyPair keys = RSAUtils.generateKeyPair();
        this.publicKey = keys.getPublic();
        this.privateKey = keys.getPrivate();

        RSABlindingFactorGenerator rsaBlindingFactorGenerator = new RSABlindingFactorGenerator();
        rsaBlindingFactorGenerator.init(publicKey);
        BigInteger blindingFactor = rsaBlindingFactorGenerator.generateBlindingFactor();

        this.blindingParameters = new RSABlindingParameters(publicKey, blindingFactor);
    }

    /**
     * The message gets blinded and then afterwards it gets signed.
     *
     * @param message original Message
     * @return blind signature of that original message
     */
    public byte[] blindMessage(byte[] message) {
        // Initialize blind signature classes of bouncycastle with
        // SHA256 and a predefined saltlength
        this.blindSigner = new PSSSigner(new RSABlindingEngine(), new SHA256Digest(), this.saltL);
        this.blindSigner.init(true, this.blindingParameters);
        this.blindSigner.update(message, 0, message.length);

        // Blind before signing
        byte[] blindMessage = null;
        try {
            blindMessage = this.blindSigner.generateSignature();
        } catch (CryptoException e) {
            LOG.error("Blinding message failed");
            e.printStackTrace();
        }

        if(blindMessage == null) {
            return null;
        }
        return blindMessage;
    }

    public String blindMessage(String message) {
        return MessageUtils.encodeBytes(this.blindMessage(MessageUtils.decodeToBytes(message)));
    }

    /**
     * Unblinds a given message
     *
     * @param blindedMessage
     * @return unblinded Message
     */
    public byte[] unblind(byte[] blindedMessage) {
        LOG.info("Unblinding message");
        RSABlindingEngine blindingEngine = new RSABlindingEngine();
        blindingEngine.init(false, this.blindingParameters);
        return blindingEngine.processBlock(blindedMessage, 0, blindedMessage.length);
    }

    public String unblind(String blindedMessage) {
        return MessageUtils.encodeBytes(this.unblind(MessageUtils.decodeToBytes(blindedMessage)));
    }

    /**
     * The blindSignature must be unblinded first
     * Then initialize the verifying process by setting up the public key
     * and verify it with the unblinded message if it matches the original message
     *
     * @param unblindedSignature
     * @param originalMessage
     * @param otherPublicKey - Public key from SP
     * @return boolean
     */

    public boolean verify(byte[] unblindedSignature, byte[] originalMessage, AsymmetricKeyParameter otherPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PSSSigner pssEng = new PSSSigner(new RSAEngine(), new SHA256Digest(), this.saltL);
        pssEng.init(false, otherPublicKey);
        pssEng.update(originalMessage, 0, originalMessage.length);
        boolean pass = pssEng.verifySignature(unblindedSignature);

        if(pass) {
            LOG.info("Verifying blind signature - Pass");
        } else {
            LOG.error("Verifying blind signature - Failed");
        }

        return pass;
    }


    public boolean verify(byte[] blindSignature, byte[] originalMessage) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return verify(blindSignature, originalMessage, this.publicKey);
    }

    public boolean verify(byte[] blindSignature, Reputationtoken originalToken) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return this.verify(blindSignature, originalToken.getBytes());
    }
}
