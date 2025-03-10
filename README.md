# sm2-duplicate-sign

    在传统的数字签名方案中，只有一个签名者能够签署一份文件，而协同签名能够改变这一点，允许多个签名者同时签署一份文件，从而提高文件的安全性。

    本项目主要提供一个需要两个参与方共同签署的签名算法实现（Java），而验证者只需使用双方机构共同提供的唯一验签公钥即可实现验证。

## 算法来源
[基于 SM2 的双方共同签名协议及其应用（苏吟雪 田海博）](http://cjc.ict.ac.cn/online/onlinepaper/009_syx-2020415163110.pdf)

## 依赖
* JAVA >= 1.8
* org.bouncycastle:bcprov-jdk15on >= 1.64(优先选择最新版本)

## 使用方法
### 前提：参与双方各自拥有一套SM2密钥对
```java
//init key
KeyPair kp1 = Sm2Utils.generate();
//KeyPair kp2;
```

### 初始化：使用自己的私钥和对方的公钥生产签名器
```java
//init digest
DuplicateSignDigest digest1 = new DuplicateSignDigest(
        (BCECPrivateKey) kp1.getPrivate()
        , (BCECPublicKey) kp2.getPublic()
);
//DuplicateSignDigest digest1;
```

### 获取验签公钥：
```java
//build verify key
PublicKey validKey = digest1.takeVerifyKey();
```

### 启动签名会话：
```java
DuplicateSignDigest.Session s1 = digest1.startSession();
//DuplicateSignDigest.Session s2;
```

### 签名
* 见Demo

### 验签：
（常用的SM2验签即可，标准见国密局发布的《SM2椭圆曲线公钥密码算法 - 第2部分:数字签名算法》）
```java
//PublicKey validKey; //见【获取验签公钥】
boolean result = Sm2Utils.verify(msg, sign, validKey.getEncoded());
//BCSm2Utils.verify(data, sign, pubKey, id)适用于指定了签名者的ID
System.out.println("验签结果：" + result);
```

## 示例
在top.ivan.sm2.example包下提供了两个Demo:
* DuplicateSignDemo: 完整签名步骤演示
* CSDemo: 模拟了签名发起方与参与方，通过RPC调用完成协同签名的过程


