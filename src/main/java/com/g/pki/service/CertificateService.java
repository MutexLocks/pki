package com.g.pki.service;

public interface CertificateService {
    byte[] generateCert(String csrCode);
}
