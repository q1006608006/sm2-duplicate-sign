package top.ivan.sm2.example;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import top.ivan.sm2.dpsign.DuplicateSignDigest;
import top.ivan.sm2.dpsign.util.Sm2Utils;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author Ivan
 * @since 2023/03/06 14:41
 */
public class CSDemo {

    public static class DPClient extends KeyKeeper {

        private DuplicateSignDigest digest;
        private final DPServerRpc rpc;
        private String token;

        public DPClient(KeyPair ks, DPServerRpc rpc) {
            super(ks);
            this.rpc = rpc;
            init();
        }

        private void init() {
            digest = new DuplicateSignDigest(this.privateKey, rpc.getPublicKey());
            token = rpc.register(this.publicKey);
        }

        public byte[] sign(byte[] message) {
            if (verifyExpire(token)) {
                //do something
                throw new RuntimeException("expired");
            }

            DuplicateSignDigest.Session session = digest.startSession();
            String uid = UUID.randomUUID().toString();
            byte[] comMsg = session.buildSignApply(message);
            byte[] reply = rpc.apply(token, uid, comMsg);
            byte[] digits = session.buildSignRequest(reply);

            return rpc.sign(token, uid, digits);
        }
    }

    public interface DPServerRpc {

        /**
         * @param key key
         * @return token
         * @deprecated you should use a local key-map and publish a token offline instead register online
         */
        @Deprecated
        String register(BCECPublicKey key);

        /**
         * publish public-key
         *
         * @return
         */
        BCECPublicKey getPublicKey();

        /**
         * apply before sign
         *
         * @param id     cli-id
         * @param uid    random-id
         * @param comMsg cli-info & sign-message
         * @return apply info
         */
        byte[] apply(String id, String uid, byte[] comMsg);

        /**
         * sign
         *
         * @param id     cli-id
         * @param uid    random-id which generate in apply
         * @param digits sign-info
         * @return final sign
         */
        byte[] sign(String id, String uid, byte[] digits);

        /**
         * get the key for valid duplicate-sign
         *
         * @param trd client public-key
         * @return key
         */
        BCECPublicKey getVerifyKey(BCECPublicKey trd);

    }

    public static class DPServerSpi extends KeyKeeper implements DPServerRpc {
        private final Map<String, Processor> processorMap = new LinkedHashMap<String, Processor>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry eldest) {
                return this.size() > 1024;
            }
        };

        public DPServerSpi(KeyPair ks) {
            super(ks);
        }

        @Override
        public String register(BCECPublicKey key) {
            String token = UUID.randomUUID().toString();
            processorMap.put(token, new Processor(new DuplicateSignDigest(this.privateKey, key), 10));
            return token;
        }

        @Override
        public byte[] apply(String id, String uid, byte[] comMsg) {
            Processor processor;
            if (verifyExpire(id) || (processor = processorMap.get(id)) == null) {
                //do something
                throw new RuntimeException("expired");
            }

            DuplicateSignDigest.Session session = processor.getSession(uid);
            return session.signApply(comMsg);
        }

        @Override
        public byte[] sign(String id, String uid, byte[] digits) {
            Processor processor;
            if ((processor = processorMap.get(id)) == null) {
                //do something
                throw new RuntimeException("expired");
            }

            try {
                return processor.getSession(uid).sign(digits);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public BCECPublicKey getVerifyKey(BCECPublicKey trd) {
            return new DuplicateSignDigest(privateKey, trd).takeVerifyKey();
        }

        private static class Processor {
            DuplicateSignDigest digest;

            Map<String, DuplicateSignDigest.Session> sessionMap;

            public Processor(DuplicateSignDigest digest, int limit) {
                this.digest = digest;
                this.sessionMap = new LinkedHashMap<String, DuplicateSignDigest.Session>() {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<String, DuplicateSignDigest.Session> eldest) {
                        return this.size() > limit;
                    }
                };
            }

            public DuplicateSignDigest.Session getSession(String token) {
                return sessionMap.computeIfAbsent(token, key -> digest.startSession());
            }
        }
    }

    public static class KeyKeeper {
        BCECPublicKey publicKey;
        BCECPrivateKey privateKey;

        public KeyKeeper(KeyPair ks) {
            this.publicKey = (BCECPublicKey) ks.getPublic();
            this.privateKey = (BCECPrivateKey) ks.getPrivate();
        }

        public BCECPublicKey getPublicKey() {
            return publicKey;
        }
    }

    public static boolean verifyExpire(String token) {
        //verify
        return false;
    }

    public static void main(String[] args) {
        /**
         * 模拟协同签名（可信任中心或CA、签名发起方）双方在进行一次协同签名的工作流程
         *
         * 1.可信任中心（以下简称srv）提供远程服务(RPC）
         * 2.签名发起方（以下简称cli）使用srv提供的服务进行注册（该步骤仅为演示，实际
         *  应用场景中建议调整为线下对接，避免公钥在线上传播，以及更利于服务管理）
         * 3.签名，签名可拆分为以下步骤：
         *  3.0 （前置步骤）签名双方生产安全随机数
         *  3.1 cli发起签名申请，请求内容包含随机数构成信息及签名内容
         *  3.2 srv收到签名申请，验证请求内容后，返回签名要素(r,s_)
         *  3.3 cli收到(r,s_)，根据s_计算要素t
         *  3.4 cli发起签名请求，内容为(r,t)
         *  3.5 srv收到(r,t)，计算出签名(r,s)
         * 4.验签，参考《SM2椭圆曲线公钥密码算法 - 第2部分:数字签名算法》第七章节流程即
         *  可，其签名密钥可通过签名双方任意一方获得
         */

        //srv public rpc
        DPServerRpc srv = new DPServerSpi(Sm2Utils.generate());
        //cli init & register
        DPClient cli = new DPClient(Sm2Utils.generate(), srv);

        //get verify key
        BCECPublicKey validKey = srv.getVerifyKey(cli.getPublicKey());

        //test message
        byte[] msg = "this is a test message".getBytes();

        //do sign
        byte[] sign = cli.sign(msg);

        System.out.println("sign: " + Base64.getEncoder().encodeToString(sign));
        //verify sign
        System.out.println("verify: " + Sm2Utils.verify(msg, sign, validKey.getEncoded()));
    }
}
