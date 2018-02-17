package com.jcraft.jsch;

import com.jcraft.jsch.jce.SignatureDSA;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;

class KnownHostsTests {

    @Test
    void testKnownHosts() throws JSchException {
        JSch jsch = new JSch();
        jsch.setKnownHosts("~/.ssh/known_hosts");
        HostKeyRepository hostKeyRepository = jsch.getHostKeyRepository();
        HostKey[] hostKeys = hostKeyRepository.getHostKey();

        Arrays.stream(hostKeys).forEach(hostKey ->
                System.out.println(hostKey.host + " " + hostKey.type + " " + Base64.getEncoder().encodeToString(hostKey.key))
        );

        System.out.print(SignatureDSA.class.getName());
    }

}
