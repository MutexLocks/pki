

import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import com.g.pki.model.CSR;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.*;
;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import sun.misc.BASE64Encoder;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class Test {
    public Test() {
        Security.addProvider(new BouncyCastleProvider());
    }

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String genCSR(String subject, String pemPath, String pemPassword)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException {
        try {

            X509Name dn = new X509Name(subject);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair kp = keyGen.generateKeyPair();
//            PKCS10CSR p10 = new PKCS10CSR("SHA1WithRSA", dn, kp.getPublic(),
//                    new DERSet(), kp.getPrivate());
//            PKCS10CertificationRequest p10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, kp.getPublic(),
//                    new DERSet(), kp.getPrivate());
            PKCS10CertificationRequest p10 = new
                    PKCS10CertificationRequest("SHA1WithRSA", dn, kp.getPublic(),
                    null,
                    kp.getPrivate());
            // PKCS10CertificationRequest p10 = new
            // PKCS10CertificationRequest("SHA1WithRSA", dn, kp.getPublic(), new
            // DERSet(),
            // kp.getPrivate());
            byte[] der = p10.getEncoded();
            String code = "-----BEGIN CERTIFICATE REQUEST-----\n";
            code += new String(Base64.encode(der));
            code += "\n-----END CERTIFICATE REQUEST-----\n";
            CertificationRequestInfo csrinfo = p10
                    .getCertificationRequestInfo();


            String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n";
            privateKey += new BASE64Encoder().encode(kp.getPrivate().getEncoded());
            privateKey += "-----END RSA PRIVATE KEY-----\n";
            System.out.println();
            //savePEM(kp.getPrivate(), pemPassword, pemPath);

            return (kp.getPrivate()).toString();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private static void savePEM(PrivateKey key, String pemPassword,
                                String pemPath) throws Exception {
        PEMWriter writer = new PEMWriter(new FileWriter(pemPath));
        writer.writeObject(key, "DES-EDE3-CBC", pemPassword.toCharArray(),
                new SecureRandom());
        writer.close();
    }

//    public static KeyPair getPrivateKey(String pemPath, final String pemPassword)
//            throws Exception {
//        PEMReader reader = new PEMReader(new InputStreamReader(
//                new FileInputStream(pemPath)), new PasswordFinder() {
//            public char[] getPassword() {
//                // TODO Auto-generated method stub
//                return pemPassword.toCharArray();
//            }
//        });
//        KeyPair key = (KeyPair) reader.readObject();
//        return key;
//    }

    public static X509Certificate getCertificate(String caCertPath)
            throws Exception {
        X509Certificate cert;
         try (InputStream inStream = new FileInputStream("fileName-of-cert")) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate)cf.generateCertificate(inStream);
  }
//        CertificateFactory factory = new CertificateFactory();
//        FileInputStream inputStream = new FileInputStream(caCertPath);
//        X509Certificate certificate = (X509Certificate) factory
//                .engineGenerateCertificate(inputStream);
//        return certificate;
        return cert;
    }

    public static KeyPair getPrivateKey(String pemPath, final String pemPassword)
            throws Exception {
        PEMReader reader = new PEMReader(new InputStreamReader(
                new FileInputStream(pemPath)), new PasswordFinder() {
            public char[] getPassword() {
                // TODO Auto-generated method stub
                return pemPassword.toCharArray();
            }
        });
        KeyPair key = (KeyPair) reader.readObject();
        return key;
    }

    /****************************根据CSR生成证书****************************/
     public static void createUserCert(String subjectDN, String snStr,
     int validate, String caCertPath, String caPemPath,
     String caPemPassword, String userCertPath, String userPemPath,
     String userPenPassword) throws Exception {
     X509Certificate CA = getCertificate(caCertPath);
     KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
     keyGen.initialize(1024);
     KeyPair pair = keyGen.generateKeyPair();

     X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
     certGen.setSerialNumber(new BigInteger(snStr));
     certGen.setNotBefore(new Date(System.currentTimeMillis()));
     certGen.setNotAfter(new Date(System.currentTimeMillis() + validate * 24
     * 60 * 60 * 1000L));
     certGen.setSubjectDN(new X500Principal(subjectDN));
     certGen.setPublicKey(pair.getPublic());
     certGen.setIssuerDN(CA.getIssuerX500Principal());
     certGen.setSignatureAlgorithm("SHA1WithRSA");

     X509Certificate certificate = certGen.generate(pair.getPrivate());
     byte[] src = certificate.getEncoded();
     KeyPair key = getPrivateKey(caPemPath, caPemPassword);
     // byte[] b = HongAnUtils.RSASign(key.getPrivate(), src);



     X509CertImpl newcert = new X509CertImpl(src);





     X509CertInfo info = (X509CertInfo) newcert.get(newcert.getName() + "."
     + newcert.INFO);
     X509CertImpl export = new X509CertImpl(info);
     export.sign(key.getPrivate(), "SHA1WithRSA");
     savePEM(pair.getPrivate(), userPenPassword, userPemPath);
     DEROutputStream stream = new DEROutputStream(new FileOutputStream(
     userCertPath));
     stream.write(export.getEncoded());
     stream.close();
     }

    public static void main(String[] args) throws Exception {




    }

//    public CSR parseCSR() {
//         CSR csr = new CSR();
//        PKCS10CertificationRequest p10Object = new PKCS10CertificationRequest();
//
//    }

}