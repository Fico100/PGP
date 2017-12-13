package com.pgp.pgp;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPKeyRingGenerator;

import java.io.IOException;
import java.security.Security;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Security.addProvider(new BouncyCastleProvider());
        try {
            final PGPKeyRingGenerator krgen = PgpUtils.generateKeyRingGenerator("filip100janovski@gmail.com", "Password".toCharArray());
            String pgpPublicKey = PgpUtils.genPGPPublicKey(krgen);
            String pgpSecretKey = PgpUtils.genPGPPrivateKey(krgen);

            Log.d("pgpPublicKey", pgpPublicKey);
            Log.d("pgpSecretKey", pgpSecretKey);

            String encrypted = PgpUtils.encrypt("message text", pgpPublicKey);
            Log.d("encrypted ", encrypted);
            String decrypted = PgpUtils.decrypt(encrypted, "Password", pgpSecretKey);
            Log.d("decrypted ", decrypted);

        } catch (IOException | PGPException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
