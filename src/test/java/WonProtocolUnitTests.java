import msz.Message.Certificate;
import msz.Message.Reputationtoken;
import msz.Signer.BlindSignature;
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
    private Signer sp;

    // TODO we probably do not need trusted party params in this class
    private Params params;
    private BlindSignature blindSigner;


    /**
     * This is our test environment.
     *
     * We have 3 Actors: Service Provider (sp)
     *                   Requestor (r)
     *                   Supplier (s)
     *
     * The Trusted Party (tp) is necessary for ACL operations. The sole reponsibility of the
     * tp is to provide parameters to issue an anonymous session (anonymous credentials - AC)
     *
     */
    @Before
    public void createClients() {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new Signer(this.params);
        this.blindSigner = new BlindSignature();
    }

    /**
     * Checking if the certificate is correctly issued by the service provider
     */
    @Test
    public void test_registerWithSystem() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        Certificate certS = this.s.registerWithSystem(this.sp);
        Certificate certR = this.r.registerWithSystem(this.sp);

        assertTrue(this.sp.verifySignature(certS));
        assertTrue(this.sp.verifySignature(certR));
    }


    /**
     * Plain test implementation of signatures
     * This test is a simple test about creating signatures and verifying the signature (SHA256withECDSA).
     */
    @Test
    public void test_createCertificate() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        // -----------------------------
        // SP - Signer Keys
        KeyPair signerKP = ECUtils.generateKeyPair();
        PrivateKey signerPrivateKey = signerKP.getPrivate();
        PublicKey signerPublicKey = signerKP.getPublic();


        // -----------------------------
        // Client - Public Key
        PublicKey clientPublicKey = ECUtils.generateKeyPair().getPublic();  // only pubkey for client


        // -----------------------------
        // Certificate of the client - consist of Public Key and register ID
        String certificateForClient = "1,"+clientPublicKey.toString();      // public key and the ID for the registered client


        // -----------------------------
        // Algorithm of signer and client must be the same
        assertEquals(signerPrivateKey.getAlgorithm(), "EC");    // Check for elliptic curve
        assertEquals(clientPublicKey.getAlgorithm(), "EC");     // Check for elliptic curve


        // -----------------------------
        // Initialize the signature with signer private key
        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "SunEC");
        ecdsa.initSign(signerPrivateKey);


        // -----------------------------
        // We want to sign the certificate of the client
        // The signature is done upon the bytes of the certifiacte String
        ecdsa.update(certificateForClient.getBytes(StandardCharsets.UTF_8));
        byte[] signedCertificate = ecdsa.sign();


        // -----------------------------
        // Verify the Signature by initialize the verifiying process with the signers public key
        Signature verifying = Signature.getInstance("SHA256withECDSA", "SunEC");


        // -----------------------------
        // check if the signed signature is correctly signed by using the public key of the signer
        // this proves that the signature is done by the person how knows the private key of the signature
        verifying.initVerify(signerPublicKey);
        verifying.update(certificateForClient.getBytes(StandardCharsets.UTF_8));
        boolean result = verifying.verify(signedCertificate);

        Assert.assertTrue(result);
    }
}
