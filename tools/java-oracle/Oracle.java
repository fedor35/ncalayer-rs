// Тестовый оракул на проприетарном KalkanProvider из установленного NCALayer.
// Сам Kalkan в репозиторий не кладём: classpath указывает в ~/.config/NCALayer/ncalayer-cache.
// gen <dir> <password> — ключ ГОСТ-2015-512 (KZ ParamSetA), самоподписанный серт, p12, эталонная подпись.
// verify <cert.pem> <msg-utf8> <sig-hex> — проверить подпись Kalkan'ом (для подписи, сделанной Rust'ом).
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.interfaces.ECPrivateKey;
import kz.gov.pki.kalkan.jce.interfaces.ECPublicKey;
import kz.gov.pki.kalkan.x509.X509V3CertificateGenerator;
import kz.gov.pki.kalkan.jce.X509Principal;

public class Oracle {
    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x)); return s.toString(); }
    static byte[] unhex(String h) { byte[] b = new byte[h.length()/2]; for (int i=0;i<b.length;i++) b[i]=(byte)Integer.parseInt(h.substring(2*i,2*i+2),16); return b; }
    static String pem(byte[] der) { return "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der) + "\n-----END CERTIFICATE-----\n"; }

    public static void main(String[] a) throws Exception {
        Security.addProvider(new KalkanProvider());
        if (a[0].equals("gen")) gen(a[1], a[2]); else verify(a[1], a[2], a[3]);
    }

    static void gen(String dir, String pw) throws Exception {
        String msg = "ncalayer-rs test message";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2015", KalkanProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("Gost3410-2015-512-ParamSetA"));
        KeyPair kp = kpg.generateKeyPair();
        X509V3CertificateGenerator g = new X509V3CertificateGenerator();
        X509Principal dn = new X509Principal("CN=TEST GOST512,SERIALNUMBER=IIN000000000000,C=KZ");
        g.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        g.setIssuerDN(dn); g.setSubjectDN(dn);
        g.setNotBefore(new Date(System.currentTimeMillis() - 86400000L));
        g.setNotAfter(new Date(System.currentTimeMillis() + 365L*86400000L));
        g.setPublicKey(kp.getPublic());
        g.setSignatureAlgorithm("1.2.398.3.10.1.1.2.3.2");
        X509Certificate cert = g.generateX509Certificate(kp.getPrivate(), KalkanProvider.PROVIDER_NAME);
        cert.verify(kp.getPublic());

        KeyStore ks = KeyStore.getInstance("PKCS12", KalkanProvider.PROVIDER_NAME);
        ks.load(null, null);
        ks.setKeyEntry("test", kp.getPrivate(), pw.toCharArray(), new java.security.cert.Certificate[]{cert});
        try (FileOutputStream f = new FileOutputStream(dir + "/test_gost512.p12")) { ks.store(f, pw.toCharArray()); }
        try (FileWriter f = new FileWriter(dir + "/test_gost512.cer.pem")) { f.write(pem(cert.getEncoded())); }

        Signature s = Signature.getInstance("ECGOST3410-2015-512", KalkanProvider.PROVIDER_NAME);
        s.initSign(kp.getPrivate()); s.update(msg.getBytes("UTF-8")); byte[] sig = s.sign();
        MessageDigest md = MessageDigest.getInstance("GOST3411-2015-512", KalkanProvider.PROVIDER_NAME);
        ECPrivateKey priv = (ECPrivateKey) kp.getPrivate(); ECPublicKey pub = (ECPublicKey) kp.getPublic();
        try (PrintWriter f = new PrintWriter(dir + "/test_gost512.vectors")) {
            f.println("msg=" + msg);
            f.println("digest=" + hex(md.digest(msg.getBytes("UTF-8"))));
            f.println("d=" + priv.getD().toString(16));
            f.println("qx=" + pub.getQ().getX().toBigInteger().toString(16));
            f.println("qy=" + pub.getQ().getY().toBigInteger().toString(16));
            f.println("sig=" + hex(sig));
            f.println("spki=" + hex(pub.getEncoded()));
            f.println("sigalg_oid=" + cert.getSigAlgOID());
            f.println("cert_tbs=" + hex(cert.getTBSCertificate()));
            f.println("cert_sig=" + hex(cert.getSignature()));
        }
        System.out.println("ok: " + dir + " sigalg=" + cert.getSigAlgOID() + " siglen=" + sig.length);
    }

    static void verify(String certPem, String msg, String sigHex) throws Exception {
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509", KalkanProvider.PROVIDER_NAME);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(certPem));
        Signature s = Signature.getInstance("ECGOST3410-2015-512", KalkanProvider.PROVIDER_NAME);
        s.initVerify(cert.getPublicKey()); s.update(msg.getBytes("UTF-8"));
        System.out.println(s.verify(unhex(sigHex)) ? "VALID" : "INVALID");
    }
}
