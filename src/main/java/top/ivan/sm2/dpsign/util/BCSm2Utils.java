package top.ivan.sm2.dpsign.util;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

import javax.activation.UnsupportedDataTypeException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @author Ivan
 * @since 2023/03/06 14:27
 */
public class BCSm2Utils {

    /**
     * 验签，使用默认的ID（1234567812345678）
     *
     * @param data   数据原文
     * @param sign   签名
     * @param pubKey X509标准编码的公钥
     * @return 验签结果
     */
    public static boolean verifyWithX509(byte[] data, byte[] sign, byte[] pubKey) {
        //id: 1234567812345678
        byte[] id = "1234567812345678".getBytes();
        return verifyWithX509(data, sign, pubKey, id);
    }

    /**
     * 验签
     *
     * @param data   数据原文
     * @param sign   签名
     * @param pubKey X509标准编码的公钥
     * @param id id
     * @return 验签结果
     */
    public static boolean verifyWithX509(byte[] data, byte[] sign, byte[] pubKey, byte[] id) {
        try {
            PublicKey key = KeyFactory.getInstance("EC", Sm2Utils.PROVIDER).generatePublic(new X509EncodedKeySpec(pubKey));
            return verify(data, sign, key, id);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(byte[] data, byte[] sign, PublicKey key, byte[] id) {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        try {
            param = new ParametersWithID(ECUtil.generatePublicKeyParameter(key), id);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        signer.init(false, param);
        signer.update(data, 0, data.length);
        return signer.verifySignature(sign);
    }

    public static byte[] toPoint(Key key) {
        if(key instanceof ECPublicKey) {
            ECPublicKey pub = (ECPublicKey) key;
            BigInteger x = pub.getW().getAffineX();
            BigInteger y = pub.getW().getAffineY();

            byte[] bytes = new byte[64];
            System.arraycopy(x.toByteArray(), 0, bytes, 0, 32);
            System.arraycopy(y.toByteArray(), 0, bytes, 32, 32);

            System.out.println(new String(bytes));
            System.out.println(pub.getW());
            return bytes;
        } else if(key instanceof ECPrivateKey) {
            ECPrivateKey pri = (ECPrivateKey) key;
            return pri.getS().toByteArray();
        }
        throw new IllegalArgumentException("unsupported key type");
    }
}
