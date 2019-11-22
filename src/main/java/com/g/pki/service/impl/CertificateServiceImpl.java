package com.g.pki.service.impl;


import com.g.pki.service.CertificateService;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.*;
import java.math.BigInteger;
import java.security.*;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

@Service
public class CertificateServiceImpl implements CertificateService {
    private Logger LOG = LoggerFactory.getLogger(CertificateServiceImpl.class);
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

    private String issuerCSR = "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIICxzCCAa8CAQAwgYMxFzAVBgNVBAMMDid3d3cudGVzdC5jb20nMREwDwYDVQQKDAgnYW5oZW5nJzENMAsGA1UEBwwEJ2h6JzENMAsGA1UEBhMEJ0NOJzEZMBcGCSqGSIb3DQEJARYKJzFAcXEuY29tJzENMAsGA1UECwwEJ2RwJzENMAsGA1UECAwEJ2h6JzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAI+6etMba7tLNJmEM1jtO+J+/goykNH5Xxy0SGSgBXyIvIbFThMcGCCs0RL6jiYH2iPzt17qjRUyMimOYZEoCZHxqrp/d2tgBCyVu3TjxR7L6JRj9WOS5+c+dYCPmj8Kk7nzaa3fTnXeATOhpotfkOArmM1OX3MpviCMmAOf2vYGULncmhLdD97GSXYldtKsTA51z6YSzN8WhCLeh3UHnQ3dEC1/98Hmamef7LqNsAtiVgR2B9UqL2YCuMQO0kxrD5+mq3To0KFoHOA78zvpYLE4Gq7mUjpixmwoWIlxQF3kjlc6VfA9LVjYrzfwpI+iGPYvz8/NXiyovxfvkF5v9vMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAPL0AQDxqYrGayTGx7uLfNxPm9aTgITndbJyjA94WdFlW1DR3JUzVSzyIUbjv4uKVnedXRjVLvt8ksRpEK48kblsXNrniZovGs87CCb8SGbrBQiUr3XoedUWAIMMjaeUy1oc/T7Wnnhx/aHUxXzH2IPOi5e4UBGnS50YImZ+nsCfhJaLCm02IfZmXQYiaXMAAq4aa/sxGSUiKwZTMA5H3zG2ECDy3aMzxNpjPnNARGTF1in0EiTcp7wEVDbTfJrqTd3aqYEydyY/L/Dfv3d8gc9iI/bsMRCDRmG6sPT0pA+PqCOlG1V4lBS+EIgzGJckeTt/E5ZJa+cK0cBMm39pIgw==\n" +
            "-----END CERTIFICATE REQUEST-----";
    @SuppressWarnings({"deprecation", "unchecked"})

    public byte[] generateCert(String csrCode) {

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
//            Hashtable kwMapIssuer = new Hashtable();
//
//            Vector localVector = new Vector();
//
//            kwMapIssuer.put(X509Principal.C, "CN");
//
//            localVector.addElement(X509Principal.C);
//
//            kwMapIssuer.put(X509Principal.CN, "www.test.com");
//
//            localVector.addElement(X509Principal.CN);
//
//            kwMapIssuer.put(X509Principal.E, "111@qq.com");
//
//            localVector.addElement(X509Principal.E);

            certGen.setIssuerDN(parseCSRtoX509(issuerCSR));
            //  设置申请者信息

//            @SuppressWarnings("rawtypes")
//
//            Hashtable kwMapApplicant = new Hashtable();
//
//            @SuppressWarnings("rawtypes")
//
//            Vector localVectorApplicant = new Vector();
//
//            kwMapApplicant.put(X509Principal.C, "CN");
//
//            localVectorApplicant.addElement(X509Principal.C);
//
//            kwMapApplicant.put(X509Principal.CN, "wlhl");
//
//            localVectorApplicant.addElement(X509Principal.CN);
//
//            kwMapApplicant.put(X509Principal.E, "123@qq.com");
//
//            localVectorApplicant.addElement(X509Principal.E);
            certGen.setSubjectDN(parseCSRtoX509(csrCode));

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
                return cert.getEncoded();
            }
            return null;

        } catch (CertificateEncodingException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

            return null;

        }

    }

    private X509Name parseCSRtoX509(String csrCode) throws IOException {

//        String csrCode = "-----BEGIN CERTIFICATE REQUEST-----\n" +
//                "MIICxTCCAa0CAQAwgYExFzAVBgNVBAMMDid3d3cudGVzdC5jb20nMREwDwYDVQQKDAgnYW5oZW5nJzEMMAoGA1UEBwwDJzMnMQ0wCwYDVQQGEwQnQ04nMRkwFwYJKoZIhvcNAQkBFgonN0BxcS5jb20nMQwwCgYDVQQLDAMnMicxDTALBgNVBAgMBCd6aicwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCl+T+LJgaqfyq2z9UHUJYn3+GDd6dLSkqSKrPgfFG7dI4ZSMCxtSrce6X145yYgd0s2DJMHuK1nHmJ7uSbwSLIV83p3spVuemN8zLAAgQounhYbt8i+/CLPxr7GY/z4htfVRcDt3C//7Hs52zZvZPDeE1gaADrgsdI+yfFvJq4pdBnL2M2tM1fqRdqg64kfZjY/rRlR88igr1kkp+A+a5aVQpWHsD2ecghIBDrLTKHldfcg9jN+0VMcRftTRqqcmYT4wSDWNTsay7IkPx9VtX/YKmrKvSEUxZWrtpYIqbTgg0BNPNVSfu9Fnjpal9aknIWzPBM4vMbZZtE47JLLolhAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAEOE2fSnlzzQZiF+qM1eETwJx9m4b9D6cgyFhf01JAtYtIpV7G+NysG7BinZLG6tvYZWCtMTv40v7n77P2EF30EeIaKSt7Ugf9r/jt1gF9ix7z1pdY0QubWiq6XygT1VUNSFHyrbE8xH2Nmj/Ltfefv4c+yvAiwLQelFzg4w4/BLgZHFEvFTkd3PJtccYatzmXzcu/A0nFY1gc8EyFH9itKPr/bARXvm4sY+6jVKNfU8KmA6Hqo66rNZkrgXrbcB7HpCWAVVtfQERkV30uf2uYdviKDqnDQa1sVkk21X1tUx390Dp2r7TQpsyDU3WfB/cIbltcFxr4tngtvrRkbXTUc=\n" +
//                "-----END CERTIFICATE REQUEST-----\n";
        Reader reader = new StringReader(csrCode);
        PEMReader pem = new PEMReader(reader);

        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pem.readObject();
        //PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrStream);
        String compname = null;
        X509Name x509Name = null;
        if (csr == null) {
            LOG.warn("fail to parse csrcode to x509name");
        } else {
            CertificationRequestInfo certificationRequestInfo = csr.getCertificationRequestInfo();
            x509Name = certificationRequestInfo.getSubject();

            //System.out.println("x509Name is: " + x509Name + "\n");
        }
        return x509Name;
    }

    /**
     * 写文件
     *
     * @param data
     */

    @Value("${cert.save.path}")
    private String certPath;
    private void writeFile(byte[] data) {

        if (data == null) {

            return;

        }

        FileOutputStream fop = null;

        try {

            fop = new FileOutputStream(new File(certPath));

            fop.write(data);

            fop.close();

        } catch (IOException e) {

            // TODO Auto-generated catch block

            e.printStackTrace();

        }
    }

//    public static void main(String[] args) {
//
//        // TODOAuto-generated method stub
//
//        byte[] crtBuf = generateCert();
//
//        if (crtBuf != null) {
//
//            writeFile("C:\\Users\\G\\Desktop\\d\\TestCrt.crt", crtBuf);
//
//        }
//
//    }
}
