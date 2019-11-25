package com.g.pki.dao;

import com.g.pki.model.Certificate;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CertificateDao {
    String addCertificate(String certificate);
    String deleteCertificateById();
    Integer generateCertSerialNumber(Certificate certificate);
}
