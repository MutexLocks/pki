package com.g.pki.controller;

import com.g.pki.model.CSR;

import com.g.pki.service.CSRService;
import com.g.pki.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

@Controller
public class CertificateController {
    private CertificateService certificateService;
    private CSRService csrService;

    @Autowired
    public CertificateController(CertificateService certificateService, CSRService csrService) {
        this.certificateService = certificateService;
        this.csrService = csrService;
    }

    @GetMapping("/cert")
    public String index() {
        return "cert-form";
        //    model.addAttribute("X509", x509);
        // return "csr-form.html";
    }

    @Value("${cert.save.path}")
    private String certPath;

    @PostMapping("/cert")
    public ResponseEntity<InputStreamResource> getCertificate(String csrCode) throws IOException {

        String fileName = certificateService.generateCert(csrCode);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=" + fileName + ".cer");

        InputStream in = new FileInputStream(certPath + fileName + ".cer");
        return ResponseEntity
                .ok()
                .headers(headers)
                .body(new InputStreamResource(in));
        //return "auto";
    }
//    @GetMapping("/csr")
//    public String generateSCR(CSR csrParam) {
//        return csrService.getCSR(csrParam);
//    }

}
