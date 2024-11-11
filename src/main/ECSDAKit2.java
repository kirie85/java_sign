package main;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Properties;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
// import java.util.List;


public class ECSDAKit2 {

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256r1");
    public static final ECDomainParameters CURVE;
    private final ECPrivateKey eckey;
    private final String secret;


    public ECSDAKit2(String privKey) {
        try {
            this.eckey = this.generatePrivateKey(Utils.hexToBytes(privKey));
            this.secret = privKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException var3) {
            var3.printStackTrace();
            throw new RuntimeException(var3);
        }
    }

    public static String[] generateKeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(CURVE, new SecureRandom());
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters) keypair.getPublic();
        BigInteger priv = privParams.getD();
        String privHex = Utils.bytesToHex(Utils.bigIntegerToBytes(priv, 32));
        String pubHex = Utils.bytesToHex(pubParams.getQ().getEncoded(true));
        return new String[]{privHex, pubHex};
    }

    public static boolean verifyEcdsaSignature(String content, String signature, String pub) {
        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(Utils.hexToBytes(pub)), CURVE);
        signer.init(false, params);
        BigInteger[] rs = decodeFromDER(Utils.hexToBytes(signature));
        return signer.verifySignature(Utils.sha256(Utils.sha256(content.getBytes(StandardCharsets.UTF_8))), rs[0], rs[1]);
    }

    public static BigInteger[] decodeFromDER(byte[] bytes) {
        ASN1InputStream decoder = null;

        BigInteger[] var6;
        try {
            Properties.setThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer", true);
            decoder = new ASN1InputStream(bytes);
            ASN1Primitive seqObj = decoder.readObject();
            DLSequence seq = (DLSequence) seqObj;

            try {
                ASN1Integer r = (ASN1Integer) seq.getObjectAt(0);
                ASN1Integer s = (ASN1Integer) seq.getObjectAt(1);
                var6 = new BigInteger[]{r.getPositiveValue(), s.getPositiveValue()};
            } catch (ClassCastException var16) {
                throw new RuntimeException(var16);
            }
        } catch (IOException var17) {
            throw new RuntimeException(var17);
        } finally {
            if (decoder != null) {
                try {
                    decoder.close();
                } catch (IOException ignored) {
                }
            }
            Properties.removeThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer");
        }
        return var6;
    }

    public ECPrivateKey generatePrivateKey(byte[] keyBin) throws InvalidKeySpecException, NoSuchAlgorithmException {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        ECNamedCurveSpec params = new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN());
        ECPrivateKeySpec priKeySpec = new ECPrivateKeySpec(new BigInteger(keyBin), params);

        PrivateKey pKey = kf.generatePrivate(priKeySpec);
        ECPrivateKey pKey2 = (ECPrivateKey) kf.generatePrivate(priKeySpec);
        
        return (ECPrivateKey) kf.generatePrivate(priKeySpec);
    }

    public String sign(byte[] message) {
        try {
            Signature dsa = Signature.getInstance("SHA256withECDSA");
            dsa.initSign(this.eckey);
            dsa.update(Utils.sha256(message));
            return Utils.bytesToHex(dsa.sign());
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException var3) {
            var3.printStackTrace();
            throw new RuntimeException(var3);
        }
    }

    public String getPublicKey() {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECPoint pointQ = spec.getG().multiply(new BigInteger(this.secret, 16));
        byte[] publicKeyByte = pointQ.getEncoded(true);
        return Utils.bytesToHex(publicKeyByte);
    }

    static {
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    }

    public static void main(String[] args) throws UnsupportedEncodingException {
        ECSDAKit2 kit = new ECSDAKit2("7cb0b71902d58eab5c2d437fea05b92d41f6bd98f70bf4a522aef55baf7bae40");
        String data = "POST|/api/payInInfo|1730207516573|mchNo=M1727957655&payOrderId=test_payment_id";
        String s = kit.sign(data.getBytes(StandardCharsets.UTF_8));
        System.out.println(s);
        String pub = "020ed3f061203959f83d96a4428fcd4b168e70c76aff8b3db163bde81d4dc4039b";
        boolean b = verifyEcdsaSignature(data, s, pub);
        System.out.println(b);
        System.out.println(Arrays.toString(generateKeyPair()));
    }
}
