package com.pgp.pgp;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPKeyRingGenerator;

import java.io.IOException;
import java.security.Security;
import java.security.SignatureException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Security.addProvider(new BouncyCastleProvider());

        testDecryptAndVerify();
    }

    private void testEncryptAndDecrypt() {
        try {
            final PGPKeyRingGenerator krgen = PgpUtils.generateKeyRingGenerator("filip100janovski@gmail.com", "Password".toCharArray());
            String pgpPublicKey = PgpUtils.genPGPPublicKey(krgen);
            String pgpSecretKey = PgpUtils.genPGPPrivateKey(krgen);

            Log.d("pgpPublicKey", pgpPublicKey);
            Log.d("pgpSecretKey", pgpSecretKey);

            String encrypted = PgpUtils.encrypt("message text", pgpPublicKey);
            String decrypted = PgpUtils.decrypt(encrypted, "Password", pgpSecretKey);
            Log.d("decrypted ", decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void testDecryptAndVerify() {
        try {
            PgpUtils.decryptAndVerify(null, null, null, null);
        } catch (IOException | PGPException | SignatureException e) {
            e.printStackTrace();
        }
    }
}
