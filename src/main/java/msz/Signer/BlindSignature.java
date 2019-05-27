package msz.Signer;

import msz.Reputation.ReputationService;
import msz.Utils.RSAUtils;
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

/**
 * This class creates blind signatures and verifies them.
 *
 * @source: https://www.programcreek.com/java-api-examples/?code=nmldiegues/easy-vote/easy-vote-master/SIRSFramework/src/sirs/framework/criptography/CriptoUtils.java
 *          https://gist.github.com/mjethani/e6d8b3e458ff59ef5b6e
 */
public class BlindSignature {
    private static final Log LOG = LogFactory.getLog(BlindSignature.class);

    private final RSABlindingParameters blindingParameters;
    private final int saltL = 10;
    private final AsymmetricKeyParameter privateKey;
    private final AsymmetricKeyParameter publicKey;

    /**
     * Generate private and public key
     * Initialize the RSABlindingFactor of Bouncycastle
     */
    public BlindSignature() {
        AsymmetricCipherKeyPair keys = RSAUtils.generateKeyPair();
        this.publicKey = keys.getPublic();
        this.privateKey = keys.getPrivate();

        RSABlindingFactorGenerator rsaBlindingFactorGenerator = new RSABlindingFactorGenerator();
        rsaBlindingFactorGenerator.init(publicKey);
        BigInteger blindingFactor = rsaBlindingFactorGenerator.generateBlindingFactor();

        this.blindingParameters = new RSABlindingParameters((RSAKeyParameters) publicKey, blindingFactor);
    }

    /**
     * The message gets blinded and then afterwards it gets signed.
     *
     * @param message original Message
     * @return blind signature of that original message
     */
    public byte[] blindAndSign(byte[] message) {

        // Initialize blind signature classes of bouncycastle with
        // SHA256 and a predefined saltlength
        RSABlindingEngine rsaBlindedEngine = new RSABlindingEngine();
        PSSSigner blindSigner = new PSSSigner(rsaBlindedEngine, new SHA256Digest(), this.saltL);
        blindSigner.init(true, this.blindingParameters);
        blindSigner.update(message, 0, message.length);

        // Blind before signing
        byte[] blindMessage = null;
        try {
            blindMessage = blindSigner.generateSignature();
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        if(blindMessage == null) {
            return null;
        }

        // Sign it
        RSAEngine signer = new RSAEngine();
        signer.init(true, this.privateKey);
        return signer.processBlock(blindMessage, 0, blindMessage.length);
    }

    /**
     * Unblinds a given message
     *
     * @param blindedMessage
     * @return unblinded Message
     */
    private byte[] unblind(byte[] blindedMessage) {
        RSABlindingEngine rsaBlindedEngine = new RSABlindingEngine();
        rsaBlindedEngine.init(false, this.blindingParameters);
        return rsaBlindedEngine.processBlock(blindedMessage, 0, blindedMessage.length);
    }

    /**
     * The blindSignature must be unblinded first
     * Then initialize the verifying process by setting up the public key
     * and verify it with the unblinded message if it matches the original message
     *
     * @param blindSignature
     * @param originalMessage
     * @return
     */
    public boolean verify(byte[] blindSignature, byte[] originalMessage) {
        byte[] unBlinded = this.unblind(blindSignature);
        LOG.info("unblinded: " + unBlinded);

        PSSSigner signer = new PSSSigner(new RSAEngine(), new SHA256Digest(), this.saltL);
        signer.init(false, this.publicKey);
        signer.update(originalMessage, 0, originalMessage.length);
        return signer.verifySignature(unBlinded);
    }
}
