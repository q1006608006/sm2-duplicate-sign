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

        KeyPair kp1 = Sm2Utils.generate();
        KeyPair kp2 = Sm2Utils.generate();

        DuplicateSignDigest digest1 = new DuplicateSignDigest(
                (BCECPrivateKey) kp1.getPrivate()
                , (BCECPublicKey) kp2.getPublic()
        );

        DuplicateSignDigest digest2 = new DuplicateSignDigest(
                (BCECPrivateKey) kp2.getPrivate()
                , (BCECPublicKey) kp1.getPublic()
        );

        PublicKey validKey = digest1.takeValidKey();
        assert validKey.equals(digest2.takeValidKey());

        DuplicateSignDigest.Session s1 = digest1.startSession();
        DuplicateSignDigest.Session s2 = digest2.startSession();

        //stp1.
        //build sign apply
        byte[] apply = s1.buildSignApply(msg);
        //send to s2
        //
        // do apply
        byte[] reply = s2.signApply(apply);
        //send back to s1
        //

        //stp2.
        //build sign request
        byte[] digits = s1.buildSignRequest(reply);
        //send to s2
        //
        //do sign
        byte[] sign = s2.sign(digits);

        System.out.println("sign: " + bytesToHex(sign));
        System.out.println(Sm2Utils.verify(msg, sign, validKey.getEncoded()));
    }

    public static String bytesToHex(byte[] bs) {
        return Hex.toHexString(bs);
    }

}
