package top.ivan.sm2.dpsign;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class DuplicateSignDigest {
    private static final int BIG_INTEGER_PADDING = 32;
    private static final X9ECParameters sm2p256v1 = GMNamedCurves.getByName("sm2p256v1");
    private static final ECPoint g = sm2p256v1.getG();
    private static final BigInteger n = sm2p256v1.getN();

    private final BigInteger d;
    private final ECPoint b;
    private final byte[] ID;

    private BCECPublicKey v;

    private final RandomDSAKCalculator krand = new RandomDSAKCalculator();

    public DuplicateSignDigest(BCECPrivateKey pri, BCECPublicKey trd) {
        //id: 1234567812345678
        this(pri, trd, Hex.decode("31323334353637383132333435363738"));
    }

    public DuplicateSignDigest(BCECPrivateKey pri, BCECPublicKey trd, byte[] ID) {
        this.d = pri.getD();
        this.b = trd.getQ();
        krand.init(n, new SecureRandom());
        this.ID = ID;
    }


    public BCECPublicKey takeVerifyKey() {
        if (null == v) {
            ECPoint mp = ECAlgorithms.sumOfTwoMultiplies(this.b, d, g, BigInteger.valueOf(-1)).normalize();
            ECPublicKeySpec spec = new ECPublicKeySpec(mp, new ECParameterSpec(sm2p256v1.getCurve(), sm2p256v1.getG(), sm2p256v1.getN()));
            v = new BCECPublicKey("EC", spec, BouncyCastleProvider.CONFIGURATION);
        }
        return v;
    }

    public Session startSession() {
        return new Session(krand.nextK());
    }

    private byte[] getZ() {
        SM3Digest digest = new SM3Digest();
        int len = ID.length * 8;
        digest.update((byte) (len >> 8 & 0xFF));
        digest.update((byte) (len & 0xFF));
        digest.update(ID, 0, ID.length);
        digest.update(asUnsignedByteArray(sm2p256v1.getCurve().getA().toBigInteger()), 0, BIG_INTEGER_PADDING);
        digest.update(asUnsignedByteArray(sm2p256v1.getCurve().getB().toBigInteger()), 0, BIG_INTEGER_PADDING);
        digest.update(asUnsignedByteArray(g.getAffineXCoord().toBigInteger()), 0, BIG_INTEGER_PADDING);
        digest.update(asUnsignedByteArray(g.getAffineYCoord().toBigInteger()), 0, BIG_INTEGER_PADDING);
        digest.update(asUnsignedByteArray(takeVerifyKey().getQ().getAffineXCoord().toBigInteger()), 0, BIG_INTEGER_PADDING);
        digest.update(asUnsignedByteArray(takeVerifyKey().getQ().getAffineYCoord().toBigInteger()), 0, BIG_INTEGER_PADDING);

        return hashDoFinal(digest);
    }

    public class Session {
        private final BigInteger k;
        private final ECPoint[] RAndR_;
        private BigInteger r;

        private Session(BigInteger k) {
            this.k = k;
            this.RAndR_ = new ECPoint[2];
            RAndR_[0] = ECAlgorithms.referenceMultiply(g, k).normalize();
            RAndR_[1] = ECAlgorithms.referenceMultiply(b, k).normalize();
        }

        public byte[] buildS_(byte[] rb, byte[] msg) {
            verifyRR_(rb);
            ECPoint[] RbRb_ = decodeRAndR_(rb);

            this.r = getR(RAndR_[0], RbRb_[1], msg);
            BigInteger s_ = getS_();

            return asUnsignedByteArray(s_);
        }

        public byte[] getT(byte[] s_) {
            return asUnsignedByteArray(getT(fromUnsignedByteArray(s_)));
        }

        public byte[] sign(byte[] t) throws IOException {
            return toSign(r, getS(r, fromUnsignedByteArray(t)));
        }


        public byte[] getRR_() {
            byte[] data = new byte[BIG_INTEGER_PADDING * 4];
            System.arraycopy(encodePointNum(RAndR_[0].getAffineXCoord().toBigInteger(), RAndR_[0].getAffineYCoord().toBigInteger()), 0, data, 0, BIG_INTEGER_PADDING * 2);
            System.arraycopy(encodePointNum(RAndR_[1].getAffineXCoord().toBigInteger(), RAndR_[1].getAffineYCoord().toBigInteger()), 0, data, BIG_INTEGER_PADDING * 2, BIG_INTEGER_PADDING * 2);
            return data;
        }

        public void verifyRR_(byte[] rb) {
            ECPoint[] ps = decodeRAndR_(rb);
            if (!ps[1].equals(ECAlgorithms.referenceMultiply(ps[0], d))) {
                throw new RuntimeException("unknown caller");
            }
        }

        private void verifyRR_(ECPoint[] rb) {
            if (!rb[1].equals(ECAlgorithms.referenceMultiply(rb[0], d))) {
                throw new RuntimeException("unknown caller");
            }
        }

        private BigInteger getR(ECPoint ra, ECPoint rb, byte[] message) {
            ECPoint R = ECAlgorithms.sumOfTwoMultiplies(ra, BigInteger.ONE, rb, BigInteger.ONE).normalize();
            SM3Digest digest = new SM3Digest();
            updateDigest(digest, getZ());
            updateDigest(digest, message);
            return new BigInteger(1, hashDoFinal(digest)).add(R.getAffineXCoord().toBigInteger()).mod(n);
        }

        private BigInteger getS_() {
            return k.add(r).mod(n).multiply(d.modInverse(n)).mod(n);
        }

        private BigInteger getT(BigInteger s_) {
            return s_.add(k).mod(n).multiply(d.modInverse(n)).mod(n);
        }

        private BigInteger getS(BigInteger r, BigInteger t) {
            return t.subtract(r).mod(n);
        }

    }

    private static ECPoint[] decodeRAndR_(byte[] data) {
        BigInteger[] b1 = decodePointNum(data, 0);
        BigInteger[] b2 = decodePointNum(data, BIG_INTEGER_PADDING * 2);

        ECPoint p1 = sm2p256v1.getCurve().createPoint(b1[0], b1[1]);
        ECPoint p2 = sm2p256v1.getCurve().createPoint(b2[0], b2[1]);

        return new ECPoint[]{p1,p2};
    }

    private static BigInteger[] decodePointNum(byte[] data, int pos) {
        byte[] x = new byte[BIG_INTEGER_PADDING];
        byte[] y = new byte[BIG_INTEGER_PADDING];
        System.arraycopy(data, pos, x, 0, BIG_INTEGER_PADDING);
        System.arraycopy(data, pos + BIG_INTEGER_PADDING, y, 0, BIG_INTEGER_PADDING);
        return new BigInteger[]{new BigInteger(1, x), new BigInteger(1, y)};
    }

    private static byte[] encodePointNum(BigInteger x, BigInteger y) {
        byte[] data = new byte[BIG_INTEGER_PADDING * 2];
        System.arraycopy(asUnsignedByteArray(x), 0, data, 0, BIG_INTEGER_PADDING);
        System.arraycopy(asUnsignedByteArray(y), 0, data, BIG_INTEGER_PADDING * 1, BIG_INTEGER_PADDING);
        return data;
    }

    private static byte[] toSign(BigInteger r, BigInteger s) throws IOException {
        return StandardDSAEncoding.INSTANCE.encode(n, r, s);
    }

    private static void updateDigest(SM3Digest digest, byte[] data) {
        digest.update(data, 0, data.length);
    }

    private static byte[] asUnsignedByteArray(BigInteger n) {
        return BigIntegers.asUnsignedByteArray(BIG_INTEGER_PADDING, n);
    }

    private static BigInteger fromUnsignedByteArray(byte[] array) {
        return new BigInteger(1, array);
    }

    private static byte[] hashDoFinal(SM3Digest digest) {
        byte[] data = new byte[digest.getDigestSize()];
        digest.doFinal(data, 0);
        return data;
    }

}
