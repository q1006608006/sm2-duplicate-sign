package top.ivan.sm2.dpsign.util;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author Ivan
 * @since 2023/03/06 14:27
 */
public class BCSm2Utils {

    public static boolean verify(byte[] data, byte[] sign, byte[] pubKey) {
        //id: 1234567812345678
        byte[] id = Hex.decode("31323334353637383132333435363738");
        return verify(data, sign, pubKey, id);
    }

    public static boolean verify(byte[] data, byte[] sign, byte[] pubKey, byte[] id) {
        SM2Signer signer = new SM2Signer();
        CipherParameters param;
        try {
            PublicKey key = KeyFactory.getInstance("EC", Sm2Utils.PROVIDER).generatePublic(new X509EncodedKeySpec(pubKey));
            param = new ParametersWithID(ECUtil.generatePublicKeyParameter(key), id);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        signer.init(false, param);
        signer.update(data, 0, data.length);
        return signer.verifySignature(sign);
    }
}
