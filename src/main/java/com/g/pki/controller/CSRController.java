package com.g.pki.controller;

import com.g.pki.model.CSR;
import com.g.pki.service.CSRService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CSRController {
    private CSRService csrService;
    @Autowired
    public CSRController(CSRService csrService) {
        this.csrService = csrService;
    }

    @GetMapping("/")
    public String getCSRInfo() {
        return "csr-form";
    }
    @GetMapping("/csr")
    public String getCSR(CSR csrParam, Model model) {
       String[] crsCodeAndKey = csrService.getCSR(csrParam);
       model.addAttribute("csrCode", crsCodeAndKey[0]);
       model.addAttribute("privateKey", crsCodeAndKey[1]);
       return "csr-and-key";
    }
}
