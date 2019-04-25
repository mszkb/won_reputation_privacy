package msz.User;

import msz.ACL;
import msz.Message.Message;
import msz.Signer.Certificate;
import msz.Signer.Signer;
import msz.Utils.ECUtils;
import msz.TrustedParty.Params;
import msz.WonProtocol;
import org.bouncycastle.math.ec.ECPoint;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Requestor implements ACL, WonProtocol {
    private final Params params;
    private byte[] certificate;


    public Requestor(Params params) {
        this.params = params;
    }

    public Requestor(Params params, ECPoint y, Message m, String[] Attributes) {
        this.params = params;
    }

    /**
     * @see CommitmentTest
     * @source https://files.zotero.net/12620611427/From%20Zero%20Knowledge%20Proofs%20to%20Bulletproofs%20Paper%20.pdf
     */
    private void createCommitment() {
        ECPoint rnd = ECUtils.createRandomPoint(params.getGroup());

        // use h0...hn for the combined Pedersen commitment
        // use z,h0...hn for the blinded Pedersen commitment

        // sum of the commitments h0 - hn is equivalent to commitment of (h0 + ... + hn)
        // C = generator * value + randomPoint * randomness
        // C = (C1 + ... + Cn) * randomness

        // multiply each attribute with the associated ECPoint in params (hs)
        // at the end add randomness * hs0
        ECPoint commitment = rnd.multiply(this.params.getH().getAffineXCoord().toBigInteger())
                .multiply((this.params.getH().getAffineYCoord().toBigInteger()));
        for(ECPoint point : this.params.getHs()) {
//            commitment.add(point.multiply());
        }
    }

    private void createMessageToSign() {

    }

    public void setup() {
        createMessageToSign();
    }

    public void registration() {

    }

    public void preparation() {

    }

    public void validation() {

    }

    public void verifiction() {

    }

    @Override
    public void registerWithSystem() {

    }

    public Certificate registerWithSystem(Signer sp) {
        try {
            return sp.registerClient();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Certificate getCertificate() {
        return null;
    }

}
