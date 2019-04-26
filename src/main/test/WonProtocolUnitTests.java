import msz.Message.Certificate;
import msz.Message.Reputationtoken;
import msz.Signer.Signer;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import msz.Utils.ECUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;

public class WonProtocolUnitTests {

    private Requestor r;
    private Supplier s;
    private Params params;
    private Signer sp;


    @Before
    public void createClients() {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer(this.params);
    }

    @Test
    public void test_registerWithSystem() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Certificate certS = this.s.registerWithSystem(this.sp);
        Certificate certR = this.r.registerWithSystem(this.sp);

        assertTrue(this.sp.verifySignature(certS));
        assertTrue(this.sp.verifySignature(certR));
    }

    @Test
    public void test_sign_randomHash_of_other_Client() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException, NoSuchProviderException {
        Certificate certS = this.s.registerWithSystem(this.sp);
        Certificate certR = this.r.registerWithSystem(this.sp);

        assertTrue(this.sp.verifySignature(certS));
        assertTrue(this.sp.verifySignature(certR));

        String cr = this.r.createRandomHash();
        String sr = this.s.createRandomHash();

        this.r.exchangeHash(sr);
        this.s.exchangeHash(cr);

        byte[] sigR = this.r.signHash(sr);
        byte[] sigS = this.s.signHash(cr);

        assertTrue(this.r.verifySignature(sigS, cr, certS));
        assertTrue(this.s.verifySignature(sigR, sr, certR));

        Reputationtoken RTr = this.r.createReputationToken(sigS);
        Reputationtoken RTs = this.s.createReputationToken(sigR);

        // TODO interact with SP to get a blindsignature (RSA) of {certR, sigR(sr)}
        this.sp.verifiyReputationToken(RTr, cr, 5);
        this.sp.verifiyReputationToken(RTs, sr, 5);
    }

    @Test
    public void test_createCertificate() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        // TODO create certificate for requestor and supplier signed by the SP

        // Signer Keys
        KeyPair signerKP = ECUtils.generateKeyPair();
        PrivateKey signerPrivateKey = signerKP.getPrivate();
        PublicKey signerPublicKey = signerKP.getPublic();

        PublicKey clientPublicKey = ECUtils.generateKeyPair().getPublic();  // only pubkey for client
        String certificateForClient = clientPublicKey.toString()+",1";      // public key and the ID for the registered client

        assertEquals(signerPrivateKey.getAlgorithm(), "EC");    // Check for elliptic curve
        assertEquals(signerPublicKey.getAlgorithm(), "EC");     // Check for elliptic curve

        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "SunEC");
        ecdsa.initSign(signerPrivateKey);

        ecdsa.update(certificateForClient.getBytes(StandardCharsets.UTF_8));
        byte[] clientCertificate = ecdsa.sign();

        // Verify the Signature
        Signature verifying = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifying.initVerify(signerPublicKey);
        verifying.update(certificateForClient.getBytes(StandardCharsets.UTF_8));

        boolean result = verifying.verify(clientCertificate);
        Assert.assertTrue(result);
    }
}
