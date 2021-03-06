package msz.bakk.protocol.Signer;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Utils.BlindSignatureUtils;
import msz.bakk.protocol.Utils.ECUtils;
import msz.bakk.protocol.Utils.RSAUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;

public class Signer {
    
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private final AsymmetricKeyParameter publicSignatureKey;
    private final AsymmetricKeyParameter privateSignatureKey;

    private ArrayList<PublicKey> clientList = new ArrayList<>();

    private BlindSignatureUtils blindSignatureUtils;

    public Signer() {
        KeyPair signerKP = ECUtils.generateKeyPair();

        if(signerKP == null) {
            throw new NullPointerException("KeyPair generation Failed");
        }

        this.privateKey = signerKP.getPrivate();
        this.publicKey = signerKP.getPublic();

        AsymmetricCipherKeyPair keys = RSAUtils.generateKeyPair();
        this.publicSignatureKey = keys.getPublic();
        this.privateSignatureKey = keys.getPrivate();

        this.blindSignatureUtils = new BlindSignatureUtils((RSAKeyParameters) this.publicSignatureKey);
    }

    
    public Certificate registerClient(PublicKey clientPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException {
        // TODO insert into Database
        int ID = this.clientList.size() + 1;
        String rawStringToSign = clientPublicKey.toString() + "," + ID;      // public key and the ID for the registered client

        this.clientList.add(clientPublicKey);

        Signature ecdsa = Signature.getInstance("SHA256withECDSA", "SunEC");
        byte[] clientCertificate = null;
        try {
            ecdsa.initSign(this.privateKey);
            ecdsa.update(rawStringToSign.getBytes(StandardCharsets.UTF_8));
            clientCertificate = ecdsa.sign();
        } catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }

        return new Certificate(clientPublicKey, ID, clientCertificate);
    }

    public boolean verifySignature(msz.bakk.protocol.Message.Certificate certToVerify) throws SignatureException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        // Verify the Signature
        Signature certificateTextSignature = Signature.getInstance("SHA256withECDSA", "SunEC");
        certificateTextSignature.initVerify(this.publicKey);
        certificateTextSignature.update(certToVerify.getBytes());

        return certificateTextSignature.verify(certToVerify.getSignature());
    }

    public byte[] signBlindMessage(byte[] blindedToken) {
        return RSAUtils.signBlindedString(this.privateSignatureKey, blindedToken);
    }

    public boolean verify(byte[] unblindedSignature, byte[] originalMessage) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        return this.blindSignatureUtils.verify(unblindedSignature, originalMessage, this.publicSignatureKey);
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public AsymmetricKeyParameter getPublicSignatureKey() {
        return this.publicSignatureKey;
    }
}
