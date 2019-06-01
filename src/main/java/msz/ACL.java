package msz;

import org.bouncycastle.math.ec.ECPoint;

public interface ACL {
    void setup();
    void registration(ECPoint commitment);
    void preparation();
    void validation();
    void verifiction();
}
