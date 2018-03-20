package com.pgp.pgp;

import android.util.Log;

import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.ArmoredOutputStream;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.bcpg.sig.Features;
import org.spongycastle.bcpg.sig.KeyFlags;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.openpgp.PGPCompressedData;
import org.spongycastle.openpgp.PGPCompressedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPEncryptedDataGenerator;
import org.spongycastle.openpgp.PGPEncryptedDataList;
import org.spongycastle.openpgp.PGPException;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPLiteralData;
import org.spongycastle.openpgp.PGPLiteralDataGenerator;
import org.spongycastle.openpgp.PGPObjectFactory;
import org.spongycastle.openpgp.PGPOnePassSignature;
import org.spongycastle.openpgp.PGPOnePassSignatureList;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyEncryptedData;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPPublicKeyRingCollection;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureList;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.spongycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.spongycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.spongycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;

public class PgpUtils {

    private static final BcKeyFingerprintCalculator bcKeyFingerprintCalc = new BcKeyFingerprintCalculator();
    private static final String PROVIDER = "BC";

    public static String decrypt(String encryptedText, String password, String privateKey) throws Exception {
        byte[] encrypted = encryptedText.getBytes();
        InputStream in = new ByteArrayInputStream(encrypted);
        in = PGPUtil.getDecoderStream(in);
        PGPObjectFactory pgpF = new PGPObjectFactory(in, bcKeyFingerprintCalc);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        if (o == null) throw new Exception("@550 No data in message");

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        while (sKey == null && enc.getEncryptedDataObjects().hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) enc.getEncryptedDataObjects().next();
            sKey = getPrivateKey(getPGPSecretKeyRing(privateKey), pbe.getKeyID(), password.toCharArray());
        }
        if (pbe != null) {
            InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
            PGPObjectFactory pgpFact = new PGPObjectFactory(clear, bcKeyFingerprintCalc);
            PGPCompressedData cData = (PGPCompressedData) pgpFact.nextObject();
            pgpFact = new PGPObjectFactory(cData.getDataStream(), bcKeyFingerprintCalc);
            PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
            InputStream unc = ld.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                out.write(ch);
            }
            byte[] returnBytes = out.toByteArray();
            out.close();
            return new String(returnBytes);
        }
        return null;
    }

    public static String decryptAndVerify(String encryptedText, String password, String privateKey, String publicKeyString) throws IOException, SignatureException, PGPException {
        byte[] publicKeyByte = publicKeyString.getBytes();
        InputStream publicKeyIn = new ByteArrayInputStream(publicKeyByte);

        byte[] encrypted = encryptedText.getBytes();
        InputStream in = new ByteArrayInputStream(encrypted);
        in = PGPUtil.getDecoderStream(in);

        PGPObjectFactory pgpF = new PGPObjectFactory(in, bcKeyFingerprintCalc);
        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;

        while (sKey == null && it.hasNext()) {
            pbe = it.next();
            PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password.toCharArray());
            PGPSecretKey psKey = getPGPSecretKeyRing(privateKey).getSecretKey();
            if (psKey != null) {
                sKey = psKey.extractPrivateKey(decryptor);
            }
        }
        if (sKey == null) {
            throw new IllegalArgumentException("Unable to find secret key to decrypt the message");
        }

        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));


        PGPObjectFactory plainFact = new PGPObjectFactory(clear, bcKeyFingerprintCalc);

        Object message;

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData;

        message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), bcKeyFingerprintCalc);
                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                // have to read it and keep it somewhere.
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        PGPPublicKey publicKey = null;
        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            throw new PGPException("Poor PGP. Signatures not found.");
        } else {
            for (int i = 0; i < onePassSignatureList.size(); i++) {
                PGPOnePassSignature ops = onePassSignatureList.get(0);
                Log.e("decrypt","verifier : " + ops.getKeyID());
                PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(publicKeyIn), bcKeyFingerprintCalc);
                publicKey = pgpRing.getPublicKey(ops.getKeyID());
                if (publicKey != null) {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    ops.update(output);
                    PGPSignature signature = signatureList.get(i);
                    if (ops.verify(signature)) {
                        Iterator<?> userIds = publicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            String userId = (String) userIds.next();
                            Log.e("decrypt",String.format("Signed by {%s}", userId));
                        }
                        Log.e("decrypt","Signature verified");
                    } else {
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }
        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            throw new PGPException("Data is integrity protected but integrity is lost.");
        } else if (publicKey == null) {
            throw new SignatureException("Signature not found");
        } else {
            return output.toString();
        }
    }

    private static PGPPublicKey getPublicKey(PGPPublicKeyRing publicKeyRing) {
        Iterator<?> kIt = publicKeyRing.getPublicKeys();
        while (kIt.hasNext()) {
            PGPPublicKey k = (PGPPublicKey) kIt.next();
            if (k.isEncryptionKey()) {
                return k;
            }
        }
        return null;
    }

    private static PGPPrivateKey getPrivateKey(PGPSecretKeyRing keyRing, long keyID, char[] pass) throws PGPException {
        PGPSecretKey secretKey = keyRing.getSecretKey(keyID);
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
        return secretKey.extractPrivateKey(decryptor);
    }

    public static String encrypt(String msgText, String publicKey) throws IOException, PGPException {
        byte[] clearData = msgText.getBytes();
        PGPPublicKey encKey = getPublicKey(getPGPPublicKeyRing(publicKey));
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = new ArmoredOutputStream(encOut);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut);
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, clearData.length, new Date());
        pOut.write(clearData);
        lData.close();
        comData.close();
        PGPEncryptedDataGenerator encGen =
                new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(true).setSecureRandom(
                                new SecureRandom()).setProvider(PROVIDER));
        if (encKey != null) {
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(PROVIDER));
            byte[] bytes = bOut.toByteArray();
            OutputStream cOut = encGen.open(out, bytes.length);
            cOut.write(bytes);
            cOut.close();
        }
        out.close();
        return new String(encOut.toByteArray());
    }

    public final static PGPKeyRingGenerator generateKeyRingGenerator(String email, char[] pass) throws PGPException {
        RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
        kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 1024, 12));
        PGPKeyPair rsakp_sign = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), new Date());
        PGPKeyPair rsakp_enc = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), new Date());

        PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();
        signhashgen.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER | KeyFlags.SHARED);
        signhashgen.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128});
        signhashgen.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA1,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA224});
        signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
        enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        PBESecretKeyEncryptor pske = (new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, 0xc0)).build(pass);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsakp_sign,
                email, sha1Calc, signhashgen.generate(), null, new BcPGPContentSignerBuilder(rsakp_sign.getPublicKey().getAlgorithm(),
                HashAlgorithmTags.SHA1), pske);
        keyRingGen.addSubKey(rsakp_enc, enchashgen.generate(), null);
        return keyRingGen;
    }

    private static PGPPublicKeyRing getPGPPublicKeyRing(String publicKey) throws IOException {
        ArmoredInputStream ais = new ArmoredInputStream(new ByteArrayInputStream(publicKey.getBytes()));
        return (PGPPublicKeyRing) new PGPObjectFactory(ais, bcKeyFingerprintCalc).nextObject();
    }

    private static PGPSecretKeyRing getPGPSecretKeyRing(String privateKey) throws IOException {
        ArmoredInputStream ais = new ArmoredInputStream(new ByteArrayInputStream(privateKey.getBytes()));
        return (PGPSecretKeyRing) new PGPObjectFactory(ais, bcKeyFingerprintCalc).nextObject();
    }

    public final static String genPGPPublicKey(PGPKeyRingGenerator krgen) throws IOException {
        ByteArrayOutputStream baosPkr = new ByteArrayOutputStream();
        PGPPublicKeyRing pkr = krgen.generatePublicKeyRing();
        ArmoredOutputStream armoredStreamPkr = new ArmoredOutputStream(baosPkr);
        pkr.encode(armoredStreamPkr);
        armoredStreamPkr.close();
        return new String(baosPkr.toByteArray(), Charset.defaultCharset());
    }

    public final static String genPGPPrivateKey(PGPKeyRingGenerator krgen) throws IOException {
        ByteArrayOutputStream baosPriv = new ByteArrayOutputStream();
        PGPSecretKeyRing skr = krgen.generateSecretKeyRing();
        ArmoredOutputStream armoredStreamPriv = new ArmoredOutputStream(baosPriv);
        skr.encode(armoredStreamPriv);
        armoredStreamPriv.close();
        return new String(baosPriv.toByteArray(), Charset.defaultCharset());
    }
}