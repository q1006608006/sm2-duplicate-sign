package top.ivan.sm2.dpsign.util;

import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Ivan
 * @since 2023/03/05 21:00
 */
public class Sm2Utils {

    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

    public static KeyPair generate() {
        try {// 获取SM2椭圆曲线的参数
            final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
            // 获取一个椭圆曲线类型的密钥对生成器
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", PROVIDER);
            // 使用SM2的算法区域初始化密钥生成器
            kpg.initialize(sm2Spec, new SecureRandom());
            // 获取密钥对
            KeyPair keyPair = kpg.generateKeyPair();

            return keyPair;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] encrypt(byte[] plaintext, byte[] publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("EC", PROVIDER).generatePublic(new X509EncodedKeySpec(publicKey)));
            byte[] chipertext = cipher.doFinal(plaintext);

            return chipertext;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("EC", PROVIDER).generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
            byte[] plaintext = cipher.doFinal(ciphertext);

            return plaintext;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sign(byte[] src, byte[] privateKey) {
        try {
            Signature signature = Signature.getInstance("SM3withSm2", PROVIDER);
            signature.initSign(KeyFactory.getInstance("EC", PROVIDER).generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
            signature.update(src);
            return signature.sign();
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verify(byte[] src, byte[] signatureBytes, byte[] publicKey) {
        try {
            Signature signature = Signature.getInstance("SM3withSm2", PROVIDER);
            signature.initVerify(KeyFactory.getInstance("EC", PROVIDER).generatePublic(new X509EncodedKeySpec(publicKey)));
            signature.update(src);
            return signature.verify(signatureBytes);
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }

}
