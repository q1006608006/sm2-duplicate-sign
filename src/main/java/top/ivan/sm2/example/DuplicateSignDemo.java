package top.ivan.sm2.example;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import top.ivan.sm2.dpsign.DuplicateSignDigest;
import top.ivan.sm2.dpsign.util.BCSm2Utils;
import top.ivan.sm2.dpsign.util.Sm2Utils;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * @author Ivan
 * @since 2023/03/05 21:02
 */
public class DuplicateSignDemo {

    public static class SignWrapper {
        private final BCECPrivateKey privateKey;
        private final byte[] ID;
        private DuplicateSignDigest digest;
        private DuplicateSignDigest.Session session;

        public SignWrapper(BCECPrivateKey privateKey, byte[] ID) {
            this.privateKey = privateKey;
            this.ID = ID;
        }

        public SignWrapper(BCECPrivateKey privateKey) {
            this.privateKey = privateKey;
            this.ID = "1234567812345678".getBytes();
        }

        public void init(BCECPublicKey another) {
            this.digest = new DuplicateSignDigest(privateKey, another, ID);
            this.session = digest.startSession();
        }

        public byte[] getRAndR_() {
            return session.getRandomBind();
        }

        public void validRAndR_(byte[] data) {
            session.verifyRandomBind(data);
        }

        public byte[] getS_(byte[] RAndR_, byte[] message) {
            return session.buildS_(RAndR_, message);
        }

        public byte[] getT(byte[] s_) {
            return session.getT(s_);
        }

        public byte[] sign(byte[] t) throws IOException {
            return session.sign(t);
        }

        public BCECPublicKey getVerifyKey() {
            return digest.takeVerifyKey();
        }
    }


    public static void main(String[] args) throws IOException {
        String forValidSign = "for valid sign test";
        byte[] message = forValidSign.getBytes();
        byte[] ID = "0000000000000001".getBytes();

        //init user1 key
        KeyPair AliceKeyPair = Sm2Utils.generate();
        //init user2 key
        KeyPair BobKeyPair = Sm2Utils.generate();

        //构建用户Alice(使用ID 0000000000000001)
        SignWrapper Alice = new SignWrapper((BCECPrivateKey) AliceKeyPair.getPrivate(), ID);
        SignWrapper Bob = new SignWrapper((BCECPrivateKey) BobKeyPair.getPrivate());

        //初始化随机数kA
        Alice.init((BCECPublicKey) BobKeyPair.getPublic());
        //构建验证公钥
        PublicKey AliceVerifyKey = Alice.getVerifyKey();

        //初始化随机数kB
        Bob.init((BCECPublicKey) AliceKeyPair.getPublic());
        //构建验证公钥
        PublicKey BobVerifyKey = Bob.getVerifyKey();

        //1、Alice
        //生成RA和RA'
        byte[] RARA_ = Alice.getRAndR_();

        //2、Bob
        //验证RA=dB*RA'
        Bob.validRAndR_(RARA_);
        //生成RB和RB'
        byte[] RBRB_ = Bob.getRAndR_();

        //3、Alice
        //验证RB=dA*RB'
        Alice.validRAndR_(RBRB_);
        //计算R',ZA,r,返回s'
        byte[] s_ = Alice.getS_(RBRB_, message);

        //4、Bob
        //计算t
        byte[] t = Bob.getT(s_);

        //5、Alice
        //签名
        byte[] sign = Alice.sign(t);

        //验签并输出结果（注意，如果生成签名的用户（Alice）带有ID，这里的验签ID必须使用该用户ID）
        boolean AliceVerifyResult = BCSm2Utils.verify(message, sign, AliceVerifyKey.getEncoded(), ID);
        System.out.println("使用Alice关联Bob的验签公钥验签结果：" + AliceVerifyResult);

        boolean BobVerifyResult = BCSm2Utils.verify(message, sign, BobVerifyKey.getEncoded(), ID);
        System.out.println("使用Bob关联Alice的验签公钥验签结果：" + BobVerifyResult);

        boolean unknownSourceResult = BCSm2Utils.verify(message, sign, AliceKeyPair.getPublic().getEncoded(), ID);
        System.out.println("使用未关联的公钥验签结果：" + unknownSourceResult);
    }

    public static String bytesToHex(byte[] bs) {
        return Hex.toHexString(bs);
    }

}
