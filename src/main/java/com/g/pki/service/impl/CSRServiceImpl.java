package com.g.pki.service.impl;

import com.g.pki.model.CSR;
import com.g.pki.service.CSRService;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Service;

import java.security.KeyPairGenerator;
import java.security.KeyPair;


@Service
public class CSRServiceImpl implements CSRService {
    @Override
    public String[] getCSR(CSR csrParams) {
        return genCSR(csrParams.toString(), csrParams);
    }

    private String[] genCSR(String subject, CSR csrParam) {
        try {
            X509Name dn = new X509Name(subject);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(Integer.valueOf(csrParam.getEncryptionBit()));
            KeyPair keyPair = keyGen.generateKeyPair();

            PKCS10CertificationRequest p10 = new
                    PKCS10CertificationRequest(csrParam.getHashAlgorithm(), dn, keyPair.getPublic(),
                    null,
                    keyPair.getPrivate());

            byte[] der = p10.getEncoded();

            String code = "-----BEGIN CERTIFICATE REQUEST-----\n";
            code += new String(Base64.encode(der));
            code += "\n-----END CERTIFICATE REQUEST-----\n";

            der = Base64.decode(code);
            //p10 = PKCS10CertificationRequest.getCertificationRequestInfo();

            //savePEM(kp.getPrivate(), pemPassword, pemPath);
            byte[] key =keyPair.getPrivate().getEncoded();
            String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n";
            privateKey += new String(Base64.encode(key));
            privateKey += "\n-----END RSA PRIVATE KEY-----\n";

            String[] csrAndKey = new String[2];
            csrAndKey[0] = code;
            csrAndKey[1] = privateKey;
            return csrAndKey;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
}
