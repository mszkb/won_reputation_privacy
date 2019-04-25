import msz.Signer.Certificate;
import msz.TrustedParty.Params;
import msz.TrustedParty.TrustedParty;
import msz.User.Requestor;
import msz.User.Supplier;
import msz.Utils.ECUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class WonProtocolE2ETest {


    private Requestor r;
    private Supplier s;
    private Params params;
    private msz.Signer.Signer sp;


    @Before
    public void optainACL() {

    }

    @Before
    public void createClients() {
        this.params = new TrustedParty().generateParams();
        this.r = new Requestor(this.params);
        this.s = new Supplier(this.params);
        this.sp = new msz.Signer.Signer(this.params);
    }


    @Test
    public void test_registerWithSystem() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        msz.Signer.Certificate certS = this.s.registerWithSystem(this.sp);
        Certificate certR = this.r.registerWithSystem(this.sp);

        assertTrue(this.sp.verifySignature(certS));
        assertTrue(this.sp.verifySignature(certR));
    }


    @Test
    public void exchangeReputationToken() {
        // TODO create Hash User
        // TODO create Hash Supplier

        // TODO User - send cert and signature of hash to SP
        // TODO Supplier - send cert and signature of hash to SP
    }
}
