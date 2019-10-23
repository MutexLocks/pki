package com.g.pki.service;

import com.g.pki.model.X509;

public interface CertificateService {
    byte[] generateCert(X509 x509);
}
