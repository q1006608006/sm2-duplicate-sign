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
        private final ECPoint[] randomBind;

        private Session(BigInteger k) {
            this.k = k;
            this.randomBind = new ECPoint[2];
            randomBind[0] = ECAlgorithms.referenceMultiply(g, k).normalize();
            randomBind[1] = ECAlgorithms.referenceMultiply(b, k).normalize();
        }

        public byte[] build(byte[] msg) {
            return encodeRandomBindMsg(randomBind, msg);
        }

        public byte[] apply(byte[] comMsg) {
            RandomBindMsg msg = decodeRandomBindMsg(comMsg);
            verifyRandomBind(msg.ps);
            BigInteger r = getR(randomBind[0], msg.ps[1], msg.msg);
            BigInteger s_ = getS_(r);
            byte[] rs_ = encodePointNum(r, s_);
            return encodeRandomBindMsg(randomBind, rs_);
        }

        public byte[] sign(byte[] digits) throws IOException {
            RandomBindMsg msg = decodeRandomBindMsg(digits);
            verifyRandomBind(msg.ps);
            BigInteger[] rs_ = decodePointNum(msg.msg, 0);
            BigInteger t = getT(rs_[1]);
            BigInteger s = getS(rs_[0], t);
            return toSign(rs_[0], s);
        }

        public byte[] getRandomBind() {
            return encodeRandomBindMsg(randomBind, new byte[0]);
        }

        public byte[] apply(byte[] rb, byte[] msg) {
            RandomBindMsg rbm = decodeRandomBindMsg(rb);
            BigInteger r = getR(randomBind[0], rbm.ps[1], msg);
            return asUnsignedByteArray(getS_(r));
        }

        public byte[] sign(byte[] rb, byte[] s_, byte[] msg) throws IOException {
            BigInteger bS_ = new BigInteger(1, s_);
            RandomBindMsg rbm = decodeRandomBindMsg(rb);
            BigInteger r = getR(randomBind[1], rbm.ps[0], msg);
            return toSign(r, getS(r, getT(bS_)));
        }

        public void verifyRandomBind(byte[] rb) {
            verifyRandomBind(decodeRandomBindMsg(rb).ps);
        }

        private void verifyRandomBind(ECPoint[] rb) {
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

        private BigInteger getS_(BigInteger r) {
            return k.add(r).mod(n).multiply(d.modInverse(n)).mod(n);
        }

        private BigInteger getT(BigInteger s_) {
            return s_.add(k).mod(n).multiply(d.modInverse(n)).mod(n);
        }

        private BigInteger getS(BigInteger r, BigInteger t) {
            return t.subtract(r).mod(n);
        }

    }

    private static class RandomBindMsg {
        public ECPoint[] ps;
        public byte[] msg;

        public RandomBindMsg(ECPoint[] ps, byte[] msg) {
            this.ps = ps;
            this.msg = msg;
        }
    }


    private static byte[] encodeRandomBindMsg(ECPoint[] r, byte[] msg) {
        byte[] data = new byte[BIG_INTEGER_PADDING * 4 + msg.length];
        System.arraycopy(encodePointNum(r[0].getAffineXCoord().toBigInteger(), r[0].getAffineYCoord().toBigInteger()), 0, data, 0, BIG_INTEGER_PADDING * 2);
        System.arraycopy(encodePointNum(r[1].getAffineXCoord().toBigInteger(), r[1].getAffineYCoord().toBigInteger()), 0, data, BIG_INTEGER_PADDING * 2, BIG_INTEGER_PADDING * 2);
        System.arraycopy(msg, 0, data, BIG_INTEGER_PADDING * 4, msg.length);
        return data;
    }

    private static RandomBindMsg decodeRandomBindMsg(byte[] data) {
        byte[] msg = new byte[data.length - BIG_INTEGER_PADDING * 4];
        System.arraycopy(data, BIG_INTEGER_PADDING * 4, msg, 0, msg.length);

        BigInteger[] b1 = decodePointNum(data, 0);
        BigInteger[] b2 = decodePointNum(data, BIG_INTEGER_PADDING * 2);

        ECPoint p1 = sm2p256v1.getCurve().createPoint(b1[0], b1[1]);
        ECPoint p2 = sm2p256v1.getCurve().createPoint(b2[0], b2[1]);
        return new RandomBindMsg(new ECPoint[]{p1, p2}, msg);
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

    private static byte[] hashDoFinal(SM3Digest digest) {
        byte[] data = new byte[digest.getDigestSize()];
        digest.doFinal(data, 0);
        return data;
    }

}
