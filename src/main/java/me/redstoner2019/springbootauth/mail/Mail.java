package me.redstoner2019.springbootauth.mail;

import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.util.Properties;

public class Mail {

    final private static String username = "sup.discordmot@gmail.com";
    final private static String password = "fogx eszz zrdk gojt";
    private static Properties props = new Properties();
    private static Session session;

    public static void init(){
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
    }

    public static void sendCreateEmail(String to, String code, String user, String displayname){
        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject("Welcome to Discord mot!");

            message.setText("Hello " + displayname + "!\n\n" +
                    "Welcome to OD Auth!\n\n" +
                    "Please enter the following code on the website to activate your account.\n\n" +
                    "```" + code + "```\n\n" +
                    "The code will expire in 15 Minutes.\n\n" +
                    "Have a nice day!");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Transport.send(message);
                    } catch (MessagingException e) {
                        throw new RuntimeException(e);
                    }
                }
            }).start();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }
}
