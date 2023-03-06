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

        BCECPublicKey getPublicKey();

        byte[] apply(String id, String uid, byte[] comMsg);

        byte[] sign(String id, String uid, byte[] digits);

        BCECPublicKey duplicateVerifyKey(BCECPublicKey trd);

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
        public BCECPublicKey duplicateVerifyKey(BCECPublicKey trd) {
            return new DuplicateSignDigest(privateKey, trd).takeValidKey();
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
        DPServerRpc dpServer = new DPServerSpi(Sm2Utils.generate());
        DPClient cli = new DPClient(Sm2Utils.generate(), dpServer);

        BCECPublicKey validKey = dpServer.duplicateVerifyKey(cli.getPublicKey());

        byte[] msg = "this is a test message".getBytes();

        byte[] sign = cli.sign(msg);
        System.out.println("sign: " + Base64.getEncoder().encodeToString(sign));
        System.out.println("verify: " + Sm2Utils.verify(msg, sign, validKey.getEncoded()));
    }
}
