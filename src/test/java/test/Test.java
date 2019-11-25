package test;

import com.g.pki.dao.CertificateDao;
import com.g.pki.service.CertificateService;
import com.g.pki.service.impl.CertificateServiceImpl;
import com.sun.org.apache.xml.internal.security.keys.keyresolver.implementations.X509SubjectNameResolver;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import sun.misc.BASE64Decoder;

import java.io.*;
import java.math.BigInteger;
import java.security.*;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

public class Test implements CertificateService {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成 X509 证书
     *
     * @return
     */

    private String publicKey = //"-----BEGIN PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRhS0DpWqGI20BUmRd+wSr9gFn\n" +
                    "HGFmkPBzuGCzscIRjDduhZO5JmAROxnF/98XM2E4SMaglm3scq1GR6+cHLLgiWIN\n" +
                    "EmGH/eAOFwiC380bFHRZZfkG8qgt2YznMBaJv6l9Cjs5Jp0q8aNaZOUi0x8K4p9S\n" +
                    "73veyePLDXQqw3uWvQIDAQAB\n" ;
    //"-----END PUBLIC KEY-----";

    private String privateKey = //"-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICXAIBAAKBgQCRhS0DpWqGI20BUmRd+wSr9gFnHGFmkPBzuGCzscIRjDduhZO5\n" +
                    "JmAROxnF/98XM2E4SMaglm3scq1GR6+cHLLgiWINEmGH/eAOFwiC380bFHRZZfkG\n" +
                    "8qgt2YznMBaJv6l9Cjs5Jp0q8aNaZOUi0x8K4p9S73veyePLDXQqw3uWvQIDAQAB\n" +
                    "AoGAGq1l+7GjDjVHYgMnSD1g9V9zkWIYDxQKKMTH4Zl4YPwqG1Zcpwg8e1ww1OYc\n" +
                    "EWZHb+iTlVQOkdbSIjy5Gm7+cbeo3NuakkRK5S4VwQzMUh7h6C/6ocdPdJX72VUH\n" +
                    "iyeIrKKCZeSIgoJRVG4EVyYauUB6IaqNMtz6JNBzVEHq9IECQQCYPbYG+dXrsWMl\n" +
                    "UY+gn5yhixvRQNiHm6nJX6vLrV8d3a1adJ3drAhP9h8dzboJ4M5rdk2IEICUwBoQ\n" +
                    "tkLhMkj9AkEA9LLYQ98mD9BOxJuezb/g+IfHNYVg6GAIfbsk+q9p6fU6yQkGQB9n\n" +
                    "X52usYnT2OVwnIwAoI7/AGRwW/6Mb+nQwQJAfQgxtwj459mH095oV0K/IO1eqzzW\n" +
                    "mIj/qKMqNNzugVjORrv/606ehQ1eANw1LmezIA7JHjZvY7thrNgDlW/3AQJBAI4z\n" +
                    "JHSEyDSmZC/jE60TlaQ4G28h3IgNzsFqMPoxWAZqyUeso+I9nbA2DSAFLYQ9CW0f\n" +
                    "+vlTQCM1Owpq6afbo8ECQEzDQk+0pQj8QuvV+ikn8B+1TCRa0ZbY73Rfj1OkyBUc\n" +
                    "LkoR9Nd92fuh2mxxPWlXutklHBk99wWd0+dsTqPb2y0=\n" ;
    //"-----END RSA PRIVATE KEY-----";

    @SuppressWarnings({"deprecation", "unchecked"})

    public String generateCert(String csrCode) {


        X509Certificate cert = null;
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        try {
            PublicKey pubKey = getPublicKey(publicKey);
            // 私钥
            PrivateKey priKey = getPrivateKey(privateKey);
            // 公钥
            certGen.setPublicKey(pubKey);
            // 设置序列号

            certGen.setSerialNumber(new BigInteger("88888"));
            Hashtable kwMapIssuer = new Hashtable();

            Vector localVector = new Vector();

            kwMapIssuer.put(X509Principal.CN, "www.root.com");
            kwMapIssuer.put(X509Principal.O, "xidian");
            kwMapIssuer.put(X509Principal.L, "xian");
            kwMapIssuer.put(X509Principal.C, "China");
            kwMapIssuer.put(X509Principal.E, "123@qq.com");
            kwMapIssuer.put(X509Principal.OU, "security");
            kwMapIssuer.put(X509Principal.ST, "shanxi");

            localVector.addElement(X509Principal.CN);
            localVector.addElement(X509Principal.O);
            localVector.addElement(X509Principal.L);
            localVector.addElement(X509Principal.C);
            localVector.addElement(X509Principal.E);
            localVector.addElement(X509Principal.OU);
            localVector.addElement(X509Principal.ST);
            certGen.setIssuerDN(new X509Principal(localVector, kwMapIssuer));
            certGen.setSubjectDN(new X509Principal(localVector, kwMapIssuer));

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
            if (cert != null) {
                writeFile(cert.getEncoded());
                // return cert.getEncoded();
            }
            return null;

        } catch (CertificateEncodingException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

            return null;
        }

    }
    private static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }
    private static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = (new BASE64Decoder()).decodeBuffer(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    private void writeFile(byte[] data) {

        if (data == null) {

            return;

        }

        FileOutputStream fop = null;

        try {

            fop = new FileOutputStream(new File("C:\\Users\\G\\Desktop\\root\\root.cer"));

            fop.write(data);

            fop.close();

        } catch (IOException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        }
    }

    public static void main(String[] args) {
        new Test().generateCert(null);
    }
}
