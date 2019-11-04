package com.g.pki.controller;

import com.g.pki.model.CSR;
import com.g.pki.model.X509;
import com.g.pki.service.CSRService;
import com.g.pki.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class CertificateController {
    private CertificateService certificateService;
    private CSRService csrService;
    @Autowired
    public CertificateController(CertificateService certificateService, CSRService csrService) {
        this.certificateService = certificateService;
        this.csrService = csrService;
    }
    @GetMapping("/test")
    public String index() {
        return "cert-form";
    //    model.addAttribute("X509", x509);
       // return "csr-form.html";
    }
    @PostMapping("/cert")
    public byte[] getCertificate(String csrCode) {

        return certificateService.generateCert(csrCode);
    }
//    @GetMapping("/csr")
//    public String generateSCR(CSR csrParam) {
//        return csrService.getCSR(csrParam);
//    }

}
