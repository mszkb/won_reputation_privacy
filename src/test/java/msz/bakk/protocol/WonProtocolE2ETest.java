import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Signer.BlindSignature;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.TrustedParty.TrustedParty;
import msz.bakk.protocol.User.Requestor;
import msz.bakk.protocol.User.Supplier;
import msz.bakk.protocol.Utils.HashUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
    private BlindSignature blindSigner;


    @Before
    public void optainACL() {

    }

    @Before
    public void createClients() throws NoSuchProviderException, NoSuchAlgorithmException {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer(this.params);
        this.blindSigner = new BlindSignature();
    }

    @Test
    public void sign_randomHash() throws NoSuchAlgorithmException {
        String randomHashAlice = HashUtils.generateRandomHash();
        LOG.info("original hash bytes " + randomHashAlice.getBytes());

        byte[] blinded = this.blindSigner.blindAndSign(randomHashAlice.getBytes(StandardCharsets.UTF_8));
        LOG.info(randomHashAlice + " blinded to " + blinded);

        LOG.info("verify blinded: " + blinded + " with " + randomHashAlice);
        assertTrue(this.blindSigner.verify(blinded, randomHashAlice.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void sign_randomHash_failVerify() throws NoSuchAlgorithmException {
        String randomHashAlice = HashUtils.generateRandomHash();
        String otherHashAlice = HashUtils.generateRandomHash();
        LOG.info("original hash bytes" + randomHashAlice.getBytes());

        byte[] blinded = this.blindSigner.blindAndSign(randomHashAlice.getBytes());
        LOG.info(randomHashAlice + " blinded to " + blinded);

        LOG.info("verify blinded: " + blinded + " with " + randomHashAlice.getBytes());
        assertFalse(this.blindSigner.verify(blinded, otherHashAlice.getBytes()));
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

        byte[] sigR = this.r.signHash();        // requestor signs supplier hash
        byte[] sigS = this.s.signHash();        // supplier signs requestor hash

        assertTrue(this.r.verifySignature(sigS, rr, certS));
        assertTrue(this.s.verifySignature(sigR, sr, certR));

        Reputationtoken RTr = this.r.createReputationToken(certR, sigR);  // requestor creates Rep token with own cert and the signed hash from supplier
        byte[] blindRTr = this.blindSigner.blindAndSign(RTr.getBytes());

        Reputationtoken RTs = this.s.createReputationToken(certS, sigS);  // supplier creates Rep token with own cert and the signed hash from requestor
        byte[] blindRTs = this.blindSigner.blindAndSign(RTs.getBytes());

        this.r.exchangeReputationToken(RTr);
        this.s.exchangeReputationToken(RTs);

        // TODO interact with SP to get a blindsignature (RSA) of {certR, sigR(sr)}
        // check signature of RT, cert and hash ... provide original number from the other user
        assertTrue(this.blindSigner.verify(blindRTr, RTr.getBytes())); // check Rep token from Requestor with original Hash
        assertTrue(this.blindSigner.verify(blindRTs, RTs.getBytes())); // check Rep token from Supplier with original Hash
    }
}
