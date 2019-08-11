import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Utils.BlindSignatureUtils;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.TrustedParty.TrustedParty;
import msz.bakk.protocol.User.Requestor;
import msz.bakk.protocol.User.Supplier;
import msz.bakk.protocol.Utils.HashUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;

/**
 * This test class tests the interaction with client and server without
 */
public class WonProtocolE2ETest {
    private static final Log LOG = LogFactory.getLog(WonProtocolE2ETest.class);

    private Requestor r;
    private Supplier s;
    private Params params;
    private Signer sp;
    private BlindSignatureUtils blindSignerAlice;
    private BlindSignatureUtils blindSignerBob;

    @Before
    public void createClients() throws NoSuchProviderException, NoSuchAlgorithmException {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer();
        this.blindSignerAlice = new BlindSignatureUtils((RSAKeyParameters) this.sp.getPublicSignatureKey());
        this.blindSignerBob = new BlindSignatureUtils((RSAKeyParameters) this.sp.getPublicSignatureKey());
    }

    @Test
    public void sign_randomHash() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String randomHashAlice = HashUtils.generateRandomHash();
        LOG.info("original send_randomhash bytes " + randomHashAlice.getBytes());

        byte[] blinded = this.blindSignerAlice.blindMessage(randomHashAlice.getBytes(StandardCharsets.UTF_8));
        LOG.info(randomHashAlice + " blinded to " + blinded);
        byte[] blindSigned = this.sp.signBlindMessage(blinded);
        byte[] unblindedSignature = this.blindSignerAlice.unblind(blindSigned);

        LOG.info("verify blinded: " + blinded + " with " + randomHashAlice);
        assertTrue(this.blindSignerAlice.verify(unblindedSignature, randomHashAlice.getBytes(StandardCharsets.UTF_8), this.sp.getPublicSignatureKey()));
    }

    @Test
    public void sign_randomHash_failVerify() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String randomHashAlice = HashUtils.generateRandomHash();
        String otherHashAlice = HashUtils.generateRandomHash();
        LOG.info("original send_randomhash bytes" + randomHashAlice.getBytes());

        byte[] blinded = this.blindSignerAlice.blindMessage(randomHashAlice.getBytes());
        LOG.info(randomHashAlice + " blinded to " + blinded);
        byte[] blindSigned = this.sp.signBlindMessage(blinded);
        byte[] unblindedSignature = this.blindSignerAlice.unblind(blindSigned);

        LOG.info("verify blinded: " + blinded + " with " + otherHashAlice.getBytes() + " - should fail");
        assertFalse(this.blindSignerAlice.verify(unblindedSignature, otherHashAlice.getBytes(), this.sp.getPublicSignatureKey()));

        LOG.info("verify blinded: " + blinded + " with " + otherHashAlice.getBytes() + " - should pass");
        assertTrue(this.blindSignerAlice.verify(unblindedSignature, randomHashAlice.getBytes(), this.sp.getPublicSignatureKey()));
    }

    /**
     * This test verifies the process of creating and exchanging reputation tokens
     *
     * Limitations: There is no socket communication. It is just a communication between java classes
     */
    @Test
    public void test_sign_randomHash_of_other_Client() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException, NoSuchProviderException {

        // Requestor and supplier register to the system and both get a certificate
        Certificate certR = this.r.registerWithSystem(this.sp);
        Certificate certS = this.s.registerWithSystem(this.sp);

        assertTrue(this.sp.verifySignature(certR));
        assertTrue(this.sp.verifySignature(certS));

        String rr = this.r.createRandomHash();  // random of Requestor
        this.s.exchangeHash(rr);                // and send it to the supplier

        String sr = this.s.createRandomHash();  // random of Supplier
        this.r.exchangeHash(sr);                // send it to the requestor

        byte[] sigR = this.r.signHash();        // requestor signs supplier send_randomhash
        byte[] sigS = this.s.signHash();        // supplier signs requestor send_randomhash

        assertTrue(this.r.verifySignature(sigS, rr, certS));
        assertTrue(this.s.verifySignature(sigR, sr, certR));

        Reputationtoken RTr = this.r.createReputationToken(certR, sigR); // requestor creates Rep token with own cert and the signed send_randomhash from supplier
        byte[] blindRTr = this.blindSignerAlice.blindMessage(RTr.getBytes()); // we blind the token first before SP recieves it
        byte[] blindSigntedRTr = this.sp.signBlindMessage(blindRTr);
        byte[] unblindedSignatureRTr = this.blindSignerAlice.unblind(blindSigntedRTr);

        Reputationtoken RTs = this.s.createReputationToken(certS, sigS); // supplier creates Rep token with own cert and the signed send_randomhash from requestor
        byte[] blindRTs = this.blindSignerBob.blindMessage(RTs.getBytes());
        byte[] blindSigntedRTs = this.sp.signBlindMessage(blindRTs);
        byte[] unblindedSignatureRTs = this.blindSignerBob.unblind(blindSigntedRTs);

        assertTrue(this.blindSignerAlice.verify(unblindedSignatureRTs, RTs.getBytes(), this.sp.getPublicSignatureKey())); // check Rep token from Requestor with original Hash
        assertTrue(this.blindSignerBob.verify(unblindedSignatureRTr, RTr.getBytes(), this.sp.getPublicSignatureKey())); // check Rep token from Supplier with original Hash
    }
}
