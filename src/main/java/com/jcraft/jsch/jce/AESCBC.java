package com.jcraft.jsch.jce;

import com.jcraft.jsch.Ciphering;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public abstract class AESCBC implements Ciphering {

    private Cipher cipher;

    @Override
    public void init(int mode, byte[] key, byte[] iv) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        String pad = "NoPadding";
        byte[] tmp;
        if (iv.length > getIVSize()) {
            tmp = new byte[getIVSize()];
            System.arraycopy(iv, 0, tmp, 0, tmp.length);
            iv = tmp;
        }
        if (key.length > getBlockSize()) {
            tmp = new byte[getBlockSize()];
            System.arraycopy(key, 0, tmp, 0, tmp.length);
            key = tmp;
        }

        SecretKeySpec keyspec = new SecretKeySpec(key, "AES");
        cipher = Cipher.getInstance("AES/CBC/" + pad);
        synchronized (Cipher.class) {
            cipher.init((mode == ENCRYPT_MODE ?
                            Cipher.ENCRYPT_MODE :
                            Cipher.DECRYPT_MODE),
                    keyspec, new IvParameterSpec(iv));
        }
    }

    @Override
    public void update(byte[] foo, int s1, int len, byte[] bar, int s2) throws ShortBufferException {
        cipher.update(foo, s1, len, bar, s2);
    }

    @Override
    public boolean isCBC() {
        return true;
    }

}
