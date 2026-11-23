// Эталон для basics.generateCsr / importCertificate: вызывает те же методы, что NCALayer
// (kz.gov.pki.provider.utils.KeyStoreUtil из бандла knca_provider_util), и проверяет наши файлы Kalkan'ом.
//   ref <dir> <defpw>                      — ключ GOST512 + CSR как в PKIEssentials.generateCsr → <dir>/ref.csr.pem
//   checkcsr <csr.pem>                     — разобрать и проверить подпись CSR Kalkan'ом, вывести DN, атрибуты, keyId
//   issue <csr.pem> <out.cer.pem>          — выпустить тестовый сертификат на CSR (свой тестовый CA, SKI = keyId, keystore ext из CSR)
//   import <dir> <defpw> <cert.pem> <newpw> — KeyStoreUtil.setX509Certificate + changePassword, как importCertificate
//   load <p12> <pw>                        — открыть p12 Kalkan'ом: алиасы, ключ/серт, подпись-проверка ключом
//   dump <p12> <pw>                        — то же + структура ASN.1 (для сравнения с нашим писателем)
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import kz.gov.pki.kalkan.Storage;
import kz.gov.pki.kalkan.asn1.*;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.pkcs.*;
import kz.gov.pki.kalkan.asn1.x509.*;
import kz.gov.pki.kalkan.asn1.util.ASN1Dump;
import kz.gov.pki.kalkan.jce.PKCS10CertificationRequest;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.util.KALKANUtils;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.gov.pki.kalkan.x509.X509V3CertificateGenerator;
import kz.gov.pki.provider.utils.CSRUtil;
import kz.gov.pki.provider.utils.KeyStoreUtil;

public class CsrOracle {
    static final String GOST512 = "1.2.398.3.10.1.1.2.3.2";

    public static void main(String[] a) throws Exception {
        Security.addProvider(new KalkanProvider());
        Provider p = Security.getProvider("KALKAN");
        switch (a[0]) {
            case "ref": ref(p, a[1], a[2]); break;
            case "checkcsr": checkCsr(a[1]); break;
            case "issue": issue(p, a[1], a[2]); break;
            case "import": doImport(p, a[1], a[2], a[3], a[4]); break;
            case "load": load(p, a[1], a[2], false); break;
            case "dump": load(p, a[1], a[2], true); break;
            default: throw new IllegalArgumentException(a[0]);
        }
    }

    static String read(String f) throws IOException { return new String(java.nio.file.Files.readAllBytes(new File(f).toPath()), "UTF-8"); }

    static void ref(Provider p, String dir, String pw) throws Exception {
        // DN как приходит с did.pki.gov.kz: {"2.5.4.4":…, "2.5.4.3":…, "2.5.4.5":…, "2.5.4.6":…, "2.5.4.42":…}
        Map<DERObjectIdentifier, String> m = new HashMap<>();
        m.put(new DERObjectIdentifier("2.5.4.4"), "ТЕСТОВ");
        m.put(new DERObjectIdentifier("2.5.4.3"), "ТЕСТОВ ТЕСТ");
        m.put(new DERObjectIdentifier("2.5.4.5"), "IIN000000000000");
        m.put(new DERObjectIdentifier("2.5.4.6"), "KZ");
        m.put(new DERObjectIdentifier("2.5.4.42"), "ТЕСТОВИЧ");
        List<DERObjectIdentifier> oids = new ArrayList<>(m.keySet());
        Collections.sort(oids, new kz.gov.pki.knca.applet.utils.NaturalOrderComparator());
        X509Name name = new X509Name(new Vector<>(oids), new Hashtable<>(m));
        X509ExtensionsGenerator eg = new X509ExtensionsGenerator();
        ASN1EncodableVector san = new ASN1EncodableVector();
        san.add(new GeneralName(1, "test@example.kz"));
        eg.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new DERSequence(san)));
        String pem = KeyStoreUtil.genKeyPairAndGetCSR(Storage.PKCS12, dir, pw.toCharArray(), GOST512, 512, name, eg, new HashSet<String>(), p);
        try (FileWriter f = new FileWriter(dir + "/ref.csr.pem")) { f.write(pem); }
        System.out.println(pem);
    }

    static void checkCsr(String file) throws Exception {
        PKCS10CertificationRequest r = CSRUtil.getPKCS10CertificationRequest(read(file));
        System.out.println("verify=" + r.verify("KALKAN"));
        CertificationRequestInfo info = r.getCertificationRequestInfo();
        System.out.println("subject=" + info.getSubject());
        System.out.println("sigalg=" + r.getSignatureAlgorithm().getObjectId());
        System.out.println("keyId=" + Hex.encodeStr(KALKANUtils.createKeyId(r.getPublicKey("KALKAN"))));
        System.out.println("pubalg=" + r.getPublicKey("KALKAN").getAlgorithm());
        System.out.println(ASN1Dump.dumpAsString(info.getAttributes(), true));
    }

    static KeyPair caKey;
    static X509Certificate caCert;

    static void issue(Provider p, String csrFile, String out) throws Exception {
        PKCS10CertificationRequest r = CSRUtil.getPKCS10CertificationRequest(read(csrFile));
        if (!r.verify("KALKAN")) throw new IllegalStateException("CSR signature invalid");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(GOST512, "KALKAN");
        kpg.initialize(512);
        caKey = kpg.genKeyPair();
        X509Name caName = new X509Name("CN=TEST CA ncalayer-rs,C=KZ");
        PublicKey pub = r.getPublicKey("KALKAN");
        X509V3CertificateGenerator g = new X509V3CertificateGenerator();
        g.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        g.setIssuerDN(caName);
        g.setSubjectDN(r.getCertificationRequestInfo().getSubject());
        g.setNotBefore(new Date(System.currentTimeMillis() - 86400000L));
        g.setNotAfter(new Date(System.currentTimeMillis() + 365L * 86400000L));
        g.setPublicKey(pub);
        g.setSignatureAlgorithm(GOST512);
        g.addExtension(X509Extensions.SubjectKeyIdentifier, false, new DEROctetString(KALKANUtils.createKeyId(pub)));
        g.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        // keystore_branch из запроса — как делает НУЦ
        ASN1Set attrs = r.getCertificationRequestInfo().getAttributes();
        for (int i = 0; attrs != null && i < attrs.size(); i++) {
            kz.gov.pki.kalkan.asn1.pkcs.Attribute at = kz.gov.pki.kalkan.asn1.pkcs.Attribute.getInstance(attrs.getObjectAt(i));
            if (!at.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) continue;
            X509Extensions ex = X509Extensions.getInstance(at.getAttrValues().getObjectAt(0));
            kz.gov.pki.kalkan.asn1.x509.X509Extension ks = ex.getExtension(KNCAObjectIdentifiers.keystore_branch);
            if (ks != null) g.addExtension(KNCAObjectIdentifiers.keystore_branch, false, ks.getValue().getOctets());
        }
        X509Certificate c = g.generateX509Certificate(caKey.getPrivate(), "KALKAN");
        try (FileWriter f = new FileWriter(out)) {
            f.write("-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(c.getEncoded()) + "\n-----END CERTIFICATE-----\n");
        }
        System.out.println("issued " + c.getSubjectDN() + " ski=" + Hex.encodeStr(KALKANUtils.createKeyId(pub)));
    }

    static void doImport(Provider p, String dir, String defpw, String certFile, String newpw) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "KALKAN");
        X509Certificate c = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
        String path = KeyStoreUtil.setX509Certificate(Storage.PKCS12, dir, defpw.toCharArray(), c, p);
        System.out.println("imported into " + path);
        KeyStoreUtil.changePassword(Storage.PKCS12, path, defpw.toCharArray(), newpw.toCharArray(), p);
        System.out.println("password changed");
    }

    static void load(Provider p, String file, String pw, boolean dump) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "KALKAN");
        try (FileInputStream in = new FileInputStream(file)) { ks.load(in, pw.toCharArray()); }
        for (String al : Collections.list(ks.aliases())) {
            System.out.println("alias=" + al + " key=" + ks.isKeyEntry(al) + " cert=" + ks.isCertificateEntry(al));
            Key k = ks.getKey(al, pw.toCharArray());
            java.security.cert.Certificate c = ks.getCertificate(al);
            java.security.cert.Certificate[] ch = ks.getCertificateChain(al);
            System.out.println("  key=" + (k == null ? null : k.getAlgorithm() + " " + k.getFormat()));
            System.out.println("  cert=" + (c == null ? null : ((X509Certificate) c).getSubjectDN()));
            System.out.println("  chain=" + (ch == null ? null : ch.length));
            if (k instanceof PrivateKey && c != null) {
                Signature s = Signature.getInstance(GOST512, "KALKAN");
                s.initSign((PrivateKey) k); s.update("x".getBytes()); byte[] sig = s.sign();
                s.initVerify(c.getPublicKey()); s.update("x".getBytes());
                System.out.println("  sign/verify with cert key: " + s.verify(sig));
            }
            if (dump && k != null) System.out.println("  pkcs8=" + Hex.encodeStr(k.getEncoded()));
        }
        if (dump) {
            ASN1InputStream in = new ASN1InputStream(new FileInputStream(file));
            System.out.println(ASN1Dump.dumpAsString(in.readObject(), true));
        }
    }
}
