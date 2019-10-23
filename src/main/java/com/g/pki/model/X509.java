package com.g.pki.model;

public class X509 {
    private String C;
    private String CN;
    private String E;
    public String getC() {
        return C;
    }

    public void setC(String c) {
        C = c;
    }

    public String getCN() {
        return CN;
    }

    public void setCN(String CN) {
        this.CN = CN;
    }

    public String getE() {
        return E;
    }

    public void setE(String e) {
        E = e;
    }

    @Override
    public String toString() {
        return "C: " + C + "CN: " + CN;
    }
}
