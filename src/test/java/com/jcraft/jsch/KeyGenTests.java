package com.jcraft.jsch;

import org.junit.jupiter.api.Test;

import java.io.IOException;

class KeyGenTests {

    @Test
    void testKeyGen() throws JSchException, IOException {
        JSch jsch = new JSch();

        KeyPair keyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA, 1024);
        keyPair.writePrivateKey("test", "secret".getBytes());
    }

}
