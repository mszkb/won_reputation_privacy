import SocketTest.Constants;
import SocketTest.TestBase;
import com.google.common.base.Utf8;
import msz.bakk.protocol.Reputation.ReputationServer;
import msz.bakk.protocol.Utils.BlindSignatureUtils;
import msz.bakk.protocol.Signer.Signer;
import msz.bakk.protocol.TrustedParty.Params;
import msz.bakk.protocol.TrustedParty.TrustedParty;
import msz.bakk.protocol.User.Requestor;
import msz.bakk.protocol.User.Supplier;
import msz.bakk.protocol.Utils.HashUtils;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.WrappedSocket;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class BlindSignatureTest extends TestBase {
    private Signer sp;
    private BlindSignatureUtils blindSigner;

    @Before
    public void createClients() throws InterruptedException, NoSuchProviderException, NoSuchAlgorithmException {
        this.sp = new Signer();
        this.blindSigner = new BlindSignatureUtils((RSAKeyParameters) this.sp.getPublicSignatureKey());
    }

    @Test
    public void test_blindSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] message = "My BLIND MESSAGE".getBytes(StandardCharsets.UTF_8);

        byte[] blindMessage = this.blindSigner.blindMessage(message);
        byte[] blindSignedMessage = this.sp.signBlindMessage(blindMessage);

        byte[] unblindedSignedMessage = this.blindSigner.unblind(blindSignedMessage);
        Assert.assertTrue(this.blindSigner.verify(unblindedSignedMessage, message, this.sp.getPublicSignatureKey()));
        Assert.assertTrue(this.sp.verify(unblindedSignedMessage, message));
    }
}
