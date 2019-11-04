package com.g.pki.model;

public class CSR {
    // 通用名称，ssl证书域名
    private String CN;
    // 组织/公司
    private String O;
    // 地理位置
    private String L;
    // 国名
    private String C;
    // hash算法
    private String hashAlgorithm;
    // 邮箱
    private String E;
    // 部门，单位
    private String OU;
    // 省份
    private String ST;
    // 加密算法
    private String encryptionAlgorithm;
    // 加密位数
    private String encryptionBit;

    public String getCN() {
        return CN;
    }

    public void setCN(String CN) {
        this.CN = CN;
    }

    public String getO() {
        return O;
    }

    public void setO(String o) {
        O = o;
    }

    public String getL() {
        return L;
    }

    public void setL(String l) {
        L = l;
    }

    public String getC() {
        return C;
    }

    public void setC(String c) {
        C = c;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getE() {
        return E;
    }

    public void setE(String e) {
        E = e;
    }

    public String getOU() {
        return OU;
    }

    public void setOU(String OU) {
        this.OU = OU;
    }

    public String getST() {
        return ST;
    }

    public void setST(String ST) {
        this.ST = ST;
    }

    public String getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public void setEncryptionAlgorithm(String encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public String getEncryptionBit() {
        return encryptionBit;
    }

    public void setEncryptionBit(String encryptionBit) {
        this.encryptionBit = encryptionBit;
    }

    @Override
    public String toString() {
        return  "CN='" + CN + '\'' +
                ", O='" + O + '\'' +
                ", L='" + L + '\'' +
                ", C='" + C + '\'' +
                ", E='" + E + '\'' +
                ", OU='" + OU + '\'' +
                ", ST='" + ST + '\'';
    }
}
