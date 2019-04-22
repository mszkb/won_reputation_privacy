package msz.Requestor;

import msz.ACL;
import msz.Utils.ECUtils;
import msz.TrustedParty.Params;
import org.bouncycastle.math.ec.ECPoint;

public class Requestor implements ACL {
    private final Params params;

    public Requestor(Params params, ECPoint y, Message m, String[] Attributes) {
        this.params = params;
    }

    private void createCommitment() {
        ECPoint rnd = ECUtils.createRandomPoint(params.getGroup());

        // use h0...hn for the combined Pedersen commitment
        // use z,h0...hn for the blinded Pedersen commitment
    }

    private void createMessageToSign() {
        Message m =
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
}
