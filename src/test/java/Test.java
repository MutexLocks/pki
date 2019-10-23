import java.io.File;

import java.io.FileOutputStream;

import java.io.IOException;

import java.math.BigInteger;

import java.security.KeyPair;

import java.security.KeyPairGenerator;

import java.security.PrivateKey;

import java.security.PublicKey;

import java.security.Security;

import java.security.cert.CertificateEncodingException;

import java.security.cert.X509Certificate;

import java.util.Calendar;

import java.util.Date;

import java.util.Hashtable;

import java.util.Vector;

import org.bouncycastle.asn1.x509.KeyUsage;

import org.bouncycastle.asn1.x509.X509Extension;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.x509.X509V3CertificateGenerator;


@SuppressWarnings("deprecation")

public class Test {

    /**
     *BouncyCastleProvider

     */

    static {

        Security.addProvider(new BouncyCastleProvider());

    }

    /**
     * 生成 X509 证书
     *

     * @return
     */

    @SuppressWarnings({"deprecation", "unchecked"})

    public static byte[] generateCert() {

        X509Certificate cert = null;

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        try {

            // 生成RSA公私钥对

            KeyPairGenerator kpg = null;

            // 采用 RSA 非对称算法加密

            kpg = KeyPairGenerator.getInstance("RSA");


            // 初始化为2048 位

            kpg.initialize(2048);


            KeyPair keyPair = kpg.generateKeyPair();

            // 公钥

            PublicKey pubKey = keyPair.getPublic();

            // 私钥

            PrivateKey priKey = keyPair.getPrivate();


            // 公钥

            certGen.setPublicKey(pubKey);

            // 设置序列号

            certGen.setSerialNumber(new BigInteger("12345678"));

            // 设置颁发者信息

            Hashtable kwMapIssuer = new Hashtable();

            Vector localVector = new Vector();

            kwMapIssuer.put(X509Principal.C, "CN");

            localVector.addElement(X509Principal.C);

            kwMapIssuer.put(X509Principal.CN, "wuwu");

            localVector.addElement(X509Principal.CN);

            kwMapIssuer.put(X509Principal.E, "111@qq.com");

            localVector.addElement(X509Principal.E);

            certGen.setIssuerDN(new X509Principal(localVector, kwMapIssuer));

            //  设置申请者信息

            @SuppressWarnings("rawtypes")

            Hashtable kwMapApplicant = new Hashtable();

            @SuppressWarnings("rawtypes")

            Vector localVectorApplicant = new Vector();

            kwMapApplicant.put(X509Principal.C, "CN");

            localVectorApplicant.addElement(X509Principal.C);

            kwMapApplicant.put(X509Principal.CN, "wlhl");

            localVectorApplicant.addElement(X509Principal.CN);

            kwMapApplicant.put(X509Principal.E, "123@qq.com");

            localVectorApplicant.addElement(X509Principal.E);

            certGen.setSubjectDN(new X509Principal(localVectorApplicant, kwMapApplicant));

            // 设置有效期

            Calendar c = Calendar.getInstance();

            c.set(Calendar.DAY_OF_YEAR, c.get(Calendar.DAY_OF_YEAR) + 7000);

            certGen.setNotBefore(new Date());

            certGen.setNotAfter(c.getTime());

            // 设置扩展域，密钥用途

            certGen.addExtension(X509Extensions.KeyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

            // 签名算法

            certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

            cert = certGen.generateX509Certificate(priKey, "BC");

        } catch (Exception e) {

            System.out.println(e.getClass() + e.getMessage());

        }

        try {

            return cert.getEncoded();

        } catch (CertificateEncodingException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

            return null;

        }

    }

    /**
     * 写文件
     *
     * @param name
     * @param data
     */

    static public void writeFile(String name, byte[] data) {

        if (data == null) {

            return;

        }

        FileOutputStream fop = null;

        try {

            fop = new FileOutputStream(new File(name));

            fop.write(data);

            fop.close();

        } catch (IOException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        }

    }

    public static void main(String[] args) {

        // TODOAuto-generated method stub

        byte[] crtBuf = generateCert();

        if (crtBuf != null) {

            writeFile("C:\\Users\\G\\Desktop\\d\\TestCrt.crt", crtBuf);

        }

    }


}