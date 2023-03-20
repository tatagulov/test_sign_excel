import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.openxml4j.opc.PackageAccess;
import org.apache.poi.poifs.crypt.dsig.SignatureConfig;
import org.apache.poi.poifs.crypt.dsig.SignatureInfo;
import org.apache.poi.poifs.crypt.dsig.SignaturePart;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

public class Main {

    private static void sign(File tempFile) {
        try {
            // keytool -genkeypair -alias cert1 -keypass pass123 -storepass stpass123 -keyalg RSA -keystore keystore.jks
            File file = new File("cert/keystore.jks");

            KeyStore keystore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(file)) {
                keystore.load(fis, "stpass123".toCharArray());
            }

            String alias = "cert1";
            Key key = keystore.getKey(alias, "stpass123".toCharArray());
            X509Certificate x509 = (X509Certificate)keystore.getCertificate(alias);

            SignatureConfig signatureConfig = new SignatureConfig();
            signatureConfig.setKey((PrivateKey)key);
            signatureConfig.setSigningCertificateChain(Collections.singletonList(x509));

            try (OPCPackage pkg = OPCPackage.open(tempFile, PackageAccess.READ_WRITE)) {
                signatureConfig.setOpcPackage(pkg);

                SignatureInfo si = new SignatureInfo();
                si.setSignatureConfig(signatureConfig);
                si.confirmSignature();
            };

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void validate(File tempFile) {
        try {
            OPCPackage pkg = OPCPackage.open(tempFile, PackageAccess.READ);

            SignatureConfig signatureConfig = new SignatureConfig();

            SignatureInfo signatureInfo = new SignatureInfo();
            signatureInfo.setOpcPackage(pkg);
            signatureInfo.setSignatureConfig(signatureConfig);

            boolean isValid = signatureInfo.verifySignature();
            System.out.println("valid is " + isValid);
            for (SignaturePart signaturePart : signatureInfo.getSignatureParts()) {
                System.out.println("certChain: " + signaturePart.getCertChain());
                System.out.println("signer: " + signaturePart.getSigner());
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        File file = new File("test.xlsx");
        sign(file);
        validate(file);
    }
}
