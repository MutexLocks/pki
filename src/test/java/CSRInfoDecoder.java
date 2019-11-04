import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.x509.RDN;
import sun.security.x509.X500Name;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import java.util.Vector;

public class CSRInfoDecoder {

    private static Logger LOG = LoggerFactory.getLogger(CSRInfoDecoder.class);

    private static final String COUNTRY = "2.5.4.6";
    private static final String STATE = "2.5.4.8";
    private static final String LOCALE = "2.5.4.7";
    private static final String ORGANIZATION = "2.5.4.10";
    private static final String ORGANIZATION_UNIT = "2.5.4.11";
    private static final String COMMON_NAME = "2.5.4.3";
    private static final String EMAIL = "2.5.4.9";

    private static final String csrPEM = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + "MIICxDCCAawCAQAwfzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCElsbGlub2lzMRAw\n"
            + "DgYDVQQHDAdDaGljYWdvMQ4wDAYDVQQKDAVDb2RhbDELMAkGA1UECwwCTkExDjAM\n"
            + "BgNVBAMMBUNvZGFsMR4wHAYJKoZIhvcNAQkBFg9rYmF4aUBjb2RhbC5jb20wggEi\n"
            + "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSrEF27VvbGi5x7LnPk4hRigAW\n"
            + "1feGeKOmRpHd4j/kUcJZLh59NHJHg5FMF7u9YdZgnMdULawFVezJMLSJYJcCAdRR\n"
            + "hSN+skrQlB6f5wgdkbl6ZfNaMZn5NO1Ve76JppP4gl0rXHs2UkRJeb8lguOpJv9c\n"
            + "tw+Sn6B13j8jF/m/OhIYI8fWhpBYvDXukgADTloCjOIsAvRonkIpWS4d014deKEe\n"
            + "5rhYX67m3H7GtZ/KVtBKhg44ntvuT2fR/wB1FlDws+0gp4edlkDlDml1HXsf4FeC\n"
            + "ogijo6+C9ewC2anpqp9o0CSXM6BT2I0h41PcQPZ4EtAc4ctKSlzTwaH0H9MbAgMB\n"
            + "AAGgADANBgkqhkiG9w0BAQsFAAOCAQEAqfQbrxc6AtjymI3TjN2upSFJS57FqPSe\n"
            + "h1YqvtC8pThm7MeufQmK9Zd+Lk2qnW1RyBxpvWe647bv5HiQaOkGZH+oYNxs1XvM\n"
            + "y5huq+uFPT5StbxsAC9YPtvD28bTH7iXR1b/02AK2rEYT8a9/tCBCcTfaxMh5+fr\n"
            + "maJtj+YPHisjxKW55cqGbotI19cuwRogJBf+ZVE/4hJ5w/xzvfdKjNxTcNr1EyBE\n"
            + "8ueJil2Utd1EnVrWbmHQqnlAznLzC5CKCr1WfmnrDw0GjGg1U6YpjKBTc4MDBQ0T\n"
            + "56ZL2yaton18kgeoWQVgcbK4MXp1kySvdWq0Bc3pmeWSM9lr/ZNwNQ==\n"
            + "-----END CERTIFICATE REQUEST-----\n";

    public static void main(String[] args) throws Exception{
        readCertificateSigningRequest();
    }

    public static String readCertificateSigningRequest() throws Exception {
        //String csrSring = "MIICxTCCAa0CAQAwgYExFzAVBgNVBAMMDid3d3cudGVzdC5jb20nMREwDwYDVQQKDAgnYW5oZW5nJzEMMAoGA1UEBwwDJzMnMQ0wCwYDVQQGEwQnQ04nMRkwFwYJKoZIhvcNAQkBFgonN0BxcS5jb20nMQwwCgYDVQQLDAMnMicxDTALBgNVBAgMBCd6aicwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCl+T+LJgaqfyq2z9UHUJYn3+GDd6dLSkqSKrPgfFG7dI4ZSMCxtSrce6X145yYgd0s2DJMHuK1nHmJ7uSbwSLIV83p3spVuemN8zLAAgQounhYbt8i+/CLPxr7GY/z4htfVRcDt3C//7Hs52zZvZPDeE1gaADrgsdI+yfFvJq4pdBnL2M2tM1fqRdqg64kfZjY/rRlR88igr1kkp+A+a5aVQpWHsD2ecghIBDrLTKHldfcg9jN+0VMcRftTRqqcmYT4wSDWNTsay7IkPx9VtX/YKmrKvSEUxZWrtpYIqbTgg0BNPNVSfu9Fnjpal9aknIWzPBM4vMbZZtE47JLLolhAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAEOE2fSnlzzQZiF+qM1eETwJx9m4b9D6cgyFhf01JAtYtIpV7G+NysG7BinZLG6tvYZWCtMTv40v7n77P2EF30EeIaKSt7Ugf9r/jt1gF9ix7z1pdY0QubWiq6XygT1VUNSFHyrbE8xH2Nmj/Ltfefv4c+yvAiwLQelFzg4w4/BLgZHFEvFTkd3PJtccYatzmXzcu/A0nFY1gc8EyFH9itKPr/bARXvm4sY+6jVKNfU8KmA6Hqo66rNZkrgXrbcB7HpCWAVVtfQERkV30uf2uYdviKDqnDQa1sVkk21X1tUx390Dp2r7TQpsyDU3WfB/cIbltcFxr4tngtvrRkbXTUc=\n";
        //String csrStringDecode = new Base64.Decoder(csrSring);

        String csrCode = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                "MIICxTCCAa0CAQAwgYExFzAVBgNVBAMMDid3d3cudGVzdC5jb20nMREwDwYDVQQKDAgnYW5oZW5nJzEMMAoGA1UEBwwDJzMnMQ0wCwYDVQQGEwQnQ04nMRkwFwYJKoZIhvcNAQkBFgonN0BxcS5jb20nMQwwCgYDVQQLDAMnMicxDTALBgNVBAgMBCd6aicwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCl+T+LJgaqfyq2z9UHUJYn3+GDd6dLSkqSKrPgfFG7dI4ZSMCxtSrce6X145yYgd0s2DJMHuK1nHmJ7uSbwSLIV83p3spVuemN8zLAAgQounhYbt8i+/CLPxr7GY/z4htfVRcDt3C//7Hs52zZvZPDeE1gaADrgsdI+yfFvJq4pdBnL2M2tM1fqRdqg64kfZjY/rRlR88igr1kkp+A+a5aVQpWHsD2ecghIBDrLTKHldfcg9jN+0VMcRftTRqqcmYT4wSDWNTsay7IkPx9VtX/YKmrKvSEUxZWrtpYIqbTgg0BNPNVSfu9Fnjpal9aknIWzPBM4vMbZZtE47JLLolhAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAEOE2fSnlzzQZiF+qM1eETwJx9m4b9D6cgyFhf01JAtYtIpV7G+NysG7BinZLG6tvYZWCtMTv40v7n77P2EF30EeIaKSt7Ugf9r/jt1gF9ix7z1pdY0QubWiq6XygT1VUNSFHyrbE8xH2Nmj/Ltfefv4c+yvAiwLQelFzg4w4/BLgZHFEvFTkd3PJtccYatzmXzcu/A0nFY1gc8EyFH9itKPr/bARXvm4sY+6jVKNfU8KmA6Hqo66rNZkrgXrbcB7HpCWAVVtfQERkV30uf2uYdviKDqnDQa1sVkk21X1tUx390Dp2r7TQpsyDU3WfB/cIbltcFxr4tngtvrRkbXTUc=\n" +
                "-----END CERTIFICATE REQUEST-----\n";
        Reader reader = new StringReader(csrCode);
        PEMReader pem = new PEMReader(reader);


        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) pem.readObject();
        //PKCS10CertificationRequest csr = convertPemToPKCS10CertificationRequest(csrStream);
        String compname = null;

        if (csr == null) {
            LOG.warn("FAIL! conversion of Pem To PKCS10 Certification Request");
        } else {

            CertificationRequestInfo certificationRequestInfo = csr.getCertificationRequestInfo();
            X509Name x509Name = certificationRequestInfo.getSubject();

            System.out.println("x509Name is: " + x509Name + "\n");

            Vector<String> csrValue = x509Name.getValues();
            for (String s : csrValue) {
                System.out.println(s);
            }
//            System.out.println(cn.getFirst().getValue().toString());
//            System.out.println(x500Name.getRDNs(BCStyle.EmailAddress)[0]);
//            System.out.println("COUNTRY: " + getX500Field(COUNTRY, x500Name));
//            System.out.println("STATE: " + getX500Field(STATE, x500Name));
//            System.out.println("LOCALE: " + getX500Field(LOCALE, x500Name));
//            System.out.println("ORGANIZATION: " + getX500Field(ORGANIZATION, x500Name));
//            System.out.println("ORGANIZATION_UNIT: " + getX500Field(ORGANIZATION_UNIT, x500Name));
//            System.out.println("COMMON_NAME: " + getX500Field(COMMON_NAME, x500Name));
//            System.out.println("EMAIL: " + getX500Field(EMAIL, x500Name));
        }
        return compname;
    }

    /**
     * 数组转对象
     *
     * @param bytes
     * @return
     */
    public static Object toObject(byte[] bytes) {
        Object obj = null;
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
            ObjectInputStream ois = new ObjectInputStream(bis);
            obj = ois.readObject();
            ois.close();
            bis.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();
        }
        return obj;
    }
//    private String getX500Field(String asn1ObjectIdentifier, X500Name x500Name) {
//        RDN[] rdnArray = x500Name.getRDNs(new ASN1ObjectIdentifier(asn1ObjectIdentifier));
//
//        String retVal = null;
//        for (RDN item : rdnArray) {
//            retVal = item.getFirst().getValue().toString();
//        }
//        return retVal;
//    }

//    private PKCS10CertificationRequest convertPemToPKCS10CertificationRequest(InputStream pem) {
//        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//        PKCS10CertificationRequest csr = null;
//        ByteArrayInputStream pemStream = null;
//
//        pemStream = (ByteArrayInputStream) pem;
//
//        Reader pemReader = new BufferedReader(new InputStreamReader(pemStream));
//        PEMParser pemParser = null;
//        try {
//            pemParser = new PEMParser(pemReader);
//            Object parsedObj = pemParser.readObject();
//            System.out.println("PemParser returned: " + parsedObj);
//            if (parsedObj instanceof PKCS10CertificationRequest) {
//                csr = (PKCS10CertificationRequest) parsedObj;
//            }
//        } catch (IOException ex) {
//            LOG.error("IOException, convertPemToPublicKey", ex);
//        } finally {
//            if (pemParser != null) {
//                IOUtils.closeQuietly(pemParser);
//            }
//        }
//        return csr;
//    }
}