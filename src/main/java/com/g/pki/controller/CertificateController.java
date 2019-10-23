package com.g.pki.controller;

import com.g.pki.model.X509;
import com.g.pki.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CertificateController {
    private CertificateService certificateService;
    @Autowired
    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }
    @GetMapping("/access")
    public byte[] getCertificate(X509 x509) {
        return certificateService.generateCert(x509);
    }
}
