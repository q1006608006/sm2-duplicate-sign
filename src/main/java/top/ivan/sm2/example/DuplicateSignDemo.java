package top.ivan.sm2.example;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.util.encoders.Hex;
import top.ivan.sm2.dpsign.DuplicateSignDigest;
import top.ivan.sm2.dpsign.util.Sm2Utils;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

/**
 * @author Ivan
 * @since 2023/03/05 21:02
 */
public class DuplicateSignDemo {


    public static void main(String[] args) throws IOException {
        String forValidSign = "for valid sign test";

        byte[] msg = forValidSign.getBytes();

        //init user1 key
        KeyPair kp1 = Sm2Utils.generate();
        //init user2 key
        KeyPair kp2 = Sm2Utils.generate();

        //init user1 digest
        DuplicateSignDigest digest1 = new DuplicateSignDigest(
                (BCECPrivateKey) kp1.getPrivate()
                , (BCECPublicKey) kp2.getPublic()
        );

        //init user2 digest
        DuplicateSignDigest digest2 = new DuplicateSignDigest(
                (BCECPrivateKey) kp2.getPrivate()
                , (BCECPublicKey) kp1.getPublic()
        );

        //build verify key
        PublicKey validKey = digest1.takeVerifyKey();
        assert validKey.equals(digest2.takeVerifyKey());
        System.out.println("public verify key: " + bytesToHex(validKey.getEncoded()));

        System.out.println("------------------fast mode (1 request)------------------");
        //start session (user1,user2)
        DuplicateSignDigest.Session s1 = digest1.startSession();
        DuplicateSignDigest.Session s2 = digest2.startSession();
        byte[] apply = s1.build(msg);
        System.out.println("s1 build sign apply(rb1,msg): " + bytesToHex(apply));

        byte[] reply = s2.apply(apply);
        System.out.println("s2 generate reply(rb2,r,s_): " + bytesToHex(reply));

        byte[] sign = s1.sign(reply);
        System.out.println("s1 generate sign(r,s): " + bytesToHex(sign));

        //verify
        System.out.println("verify result: " + Sm2Utils.verify(msg, sign, validKey.getEncoded()));

        System.out.println("------------------complex mode (at least 2 request)------------------");
        s1 = digest1.startSession();
        s2 = digest2.startSession();

        byte[] rb1 = s1.getRandomBind();
        s2.verifyRandomBind(rb1);
        System.out.println("s2 valid rb1: " + bytesToHex(rb1));

        byte[] rb2 = s2.getRandomBind();
        s1.verifyRandomBind(rb2);
        System.out.println("s1 valid rb2: " + bytesToHex(rb2));

        byte[] s_ = s2.apply(rb1, msg);
        System.out.println("s2 generate s_: " + bytesToHex(s_));

        sign = s1.sign(rb2, s_, msg);
        System.out.println("s1 generate sign(r,s) with s_: " + bytesToHex(sign));

        System.out.println("verify result: " + Sm2Utils.verify(msg, sign, validKey.getEncoded()));
    }

    public static String bytesToHex(byte[] bs) {
        return Hex.toHexString(bs);
    }

}
