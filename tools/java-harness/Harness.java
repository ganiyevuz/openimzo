import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import uz.yt.cams.us.common.context.Context;
import uz.yt.cams.us.common.pki.DocumentSigner;
import uz.yt.cams.us.common.pki.DocumentVerifier;
import uz.yt.cams.us.common.pki.dto.Pkcs7Info;
import uz.yt.cams.us.common.pki.dto.Pkcs7SignerInfo;
import uz.yt.pkix.jcajce.provider.YTProvider;

/** Cross-checks OpenImzo output with the ORIGINAL E-IMZO 6.4.7 libraries. */
public class Harness {
    static BouncyCastleProvider bcp;

    public static void main(String[] args) throws Exception {
        bcp = new BouncyCastleProvider();
        YTProvider.configure(bcp);
        Security.addProvider(bcp);
        switch (args[0]) {
            case "verify-cms":
                verifyCms(Files.readAllBytes(Paths.get(args[1])), args.length > 2 ? Files.readAllBytes(Paths.get(args[2])) : null);
                break;
            case "sign-cms":
                signCms(args[1], args[2], args[3], args[4]);
                break;
            case "read-pfx":
                readStore("PKCS12", null, args[1], args[2]);
                break;
            case "read-yks":
                readStore("YTKS-2", bcp, args[1], args[2]);
                break;
            default:
                System.err.println("usage: verify-cms <p7> [content] | sign-cms <pfx> <password> <content> <out> | read-pfx <pfx> <password> | read-yks <yks> <password>");
                System.exit(2);
        }
    }

    static void verifyCms(byte[] p7, byte[] content) throws Exception {
        DocumentVerifier v = new DocumentVerifier(bcp, null);
        Pkcs7Info info = content == null ? v.verifyPkcs7Attached(new Context(), p7) : v.verifyPkcs7Detached(new Context(), p7, content);
        boolean all = true;
        for (Pkcs7SignerInfo s : info) {
            all &= s.isVerified();
            System.out.println("signer serial=" + s.getSignerId().getSerialNumber().toString(16) + " verified=" + s.isVerified()
                    + (s.getException() != null ? " exception=" + s.getException() : ""));
        }
        System.exit(all ? 0 : 1);
    }

    static KeyStore load(String type, java.security.Provider provider, String path, String password) throws Exception {
        KeyStore ks = provider == null ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
        try (FileInputStream in = new FileInputStream(path)) {
            ks.load(in, password.toCharArray());
        }
        return ks;
    }

    static void readStore(String type, java.security.Provider provider, String path, String password) throws Exception {
        KeyStore ks = load(type, provider, path, password);
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String alias = e.nextElement();
            if (ks.isKeyEntry(alias)) {
                PrivateKey key = (PrivateKey) ks.getKey(alias, password.toCharArray());
                Certificate[] chain = ks.getCertificateChain(alias);
                System.out.println("key alias=" + alias + " algorithm=" + key.getAlgorithm() + " chain=" + chain.length
                        + " subject=" + ((X509Certificate) chain[0]).getSubjectDN().getName());
            } else {
                System.out.println("cert alias=" + alias + " subject=" + ((X509Certificate) ks.getCertificate(alias)).getSubjectDN().getName());
            }
        }
    }

    static void signCms(String pfx, String password, String contentPath, String out) throws Exception {
        KeyStore ks = load("PKCS12", null, pfx, password);
        String alias = null;
        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) { alias = a; break; }
        }
        PrivateKey key = (PrivateKey) ks.getKey(alias, password.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        X509Certificate[] x = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
        byte[] p7 = new DocumentSigner(bcp, x, key).getPkcs7(Files.readAllBytes(Paths.get(contentPath)), true);
        Files.write(Paths.get(out), p7);
        System.out.println("wrote " + out + " (" + p7.length + " bytes)");
    }
}
