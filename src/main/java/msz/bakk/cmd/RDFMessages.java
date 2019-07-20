package msz.bakk.cmd;

import msz.bakk.protocol.Message.Certificate;
import msz.bakk.protocol.Message.Reputationtoken;
import msz.bakk.protocol.Utils.MessageUtils;
import msz.bakk.protocol.Utils.WonRepRdfUtils;
import msz.bakk.protocol.vocabulary.REP;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.vocabulary.RDF;
import won.protocol.message.WonMessage;
import won.protocol.message.WonMessageBuilder;
import won.protocol.util.RdfUtils;
import won.protocol.vocabulary.CERT;
import won.protocol.vocabulary.WON;

import java.math.BigInteger;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

public class RDFMessages {

    public static WonMessage createWonMessage(Model m) {
        return WonMessageBuilder.setMessagePropertiesForConnectionMessage(
                URI.create("messageUri"),
                URI.create("localConnection"),
                URI.create("localAtom"),
                URI.create("localWonNode"),
                URI.create("targetConnection"),
                URI.create("TargetAtom"),
                URI.create("remoteWonNode"),
                m).build();
    }

    public static Model generateRandomHash() {

        String randomHash = "";
        try {
            randomHash = Utils.generateRandomHash();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return generateRandomHash(randomHash);
    }

    public static Model generateRandomHash(String hash) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);
        baseRes.addProperty(REP.RANDOM_HASH, hash);

        return model;
    }

    public static Model createCertificateResource(Certificate cert, Model model, Resource keySubject) {
        ECPublicKey publicKey = (ECPublicKey) cert.getPublicKey();
        String x = publicKey.getW().getAffineX().toString(16);
        String y  = publicKey.getW().getAffineY().toString(16);

        // EC public key triples
        Resource bn = model.createResource();
        Statement stmt = model.createStatement(bn, RDF.type, WON.ECCPublicKey);
        model.add(stmt);
        stmt = model.createStatement(bn, WON.ecc_algorithm, "EC");
        model.add(stmt);
        stmt = model.createStatement(bn, WON.ecc_curveId, "secp348r1");
        model.add(stmt);
        stmt = model.createStatement(bn, WON.ecc_qx, x);
        model.add(stmt);
        stmt = model.createStatement(bn, WON.ecc_qy, y);
        model.add(stmt);
        // public key triple
        Resource bn2 = model.createResource();
        stmt = model.createStatement(bn2, CERT.PUBLIC_KEY, bn);
        model.add(stmt);

        // backup certificate for our CLI Tool
        Resource bn3 = model.createResource();
        stmt = model.createStatement(bn3, REP.USER_ID, String.valueOf(cert.getID()));
        model.add(stmt);
        stmt = model.createStatement(bn3, REP.PUBLIC_KEY, cert.getPublicKey().toString());
        model.add(stmt);
        stmt = model.createStatement(keySubject, REP.CERTIFICATE, bn3);
        model.add(stmt);

        // key triple
        stmt = model.createStatement(keySubject, CERT.KEY, bn2);
        model.add(stmt);

        return model;
    }

    public static Model createReputationToken(String signedHash, Certificate cert) {
        Model model = WonRepRdfUtils.createBaseModel();
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);
        Resource reputationToken = model.createResource();

        createCertificateResource(cert, model, reputationToken);
        reputationToken.addProperty(REP.SIGNED_RANDOM_HASH, signedHash);
        baseRes.addProperty(REP.REPUTATIONTOKEN, reputationToken);

        return model;
    }

    public static Model blindAnswer(Reputationtoken RT, String blindSignature) {
        Model model = createReputationToken(MessageUtils.encodeBytes(RT.getSignatureOfHash()), RT.getCertificate());
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);

        Statement stmt = model.createStatement(baseRes, REP.BLIND_SIGNED_REPUTATIONTOKEN, blindSignature);
        model.add(stmt);

        return model;
    }

    public static Model rate(float rating, String message, Reputationtoken RT, String blindSignature, String originalRandom) {
        Model model = blindAnswer(RT, blindSignature);
        Resource baseRes = RdfUtils.findOrCreateBaseResource(model);

        Statement stmt = model.createStatement(baseRes, REP.RATING, String.valueOf(rating));
        model.add(stmt);
        stmt = model.createStatement(baseRes, REP.RATING_COMMENT, message);
        model.add(stmt);
        stmt = model.createStatement(baseRes, REP.ORIGINAL, originalRandom);
        model.add(stmt);

        return model;
    }
}
