package com.jcraft.jsch;

import org.junit.jupiter.api.Test;

import java.util.Vector;

class SftpTests {

    @Test
    void testSftp() throws JSchException {
        JSch jsch = new JSch();
        jsch.setKnownHosts("~/.ssh/known_hosts");

        Session session = jsch.getSession(System.getProperty("user.name"), "localhost", 22);

        HostKeyRepository hkr = jsch.getHostKeyRepository();
        for(HostKey hk : hkr.getHostKey()){
            if(hk.getHost().equals("localhost")){
                String type = hk.getType();
                session.setConfig("server_host_key", type);
            }
        }

        session.setPassword("");

        session.connect();

        Channel channel = session.openChannel("sftp");
        channel.connect();
        ChannelSftp channelSftp = (ChannelSftp)channel;

        try {
            Vector<ChannelSftp.LsEntry> vector = channelSftp.ls(".");

            vector.forEach(lsEntry -> System.out.println(lsEntry.getFilename()));
        } catch (SftpException e) {
            e.printStackTrace();
        }

        channelSftp.disconnect();

        session.disconnect();

    }

}
