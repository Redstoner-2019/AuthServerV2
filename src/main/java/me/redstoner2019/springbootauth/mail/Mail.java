package me.redstoner2019.springbootauth.mail;

import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import me.redstoner2019.springbootauth.SpringBootAuthApplication;

import javax.xml.transform.Source;
import java.io.*;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Mail {

    //final private static String username = "sup.discordmot@gmail.com";
    //final private static String password = "fogx eszz zrdk gojt";
    final private static String username = "noreply";
    final private static String password = "Optadata2025";
    private static Properties props = new Properties();
    private static Session session;

    //public static void main(String[] args) {
    //    Mail.init();
    //    Mail.sendCreateEmail("lukaspaepke2020@gmail.com","555-555","redstoner_2019","Redstoner_2019","901633313");
    //    Mail.sendLoginEmail("lukaspaepke2020@gmail.com","555-555","redstoner_2019","Redstoner_2019","901633313");
    //}

    public static void init(){
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "redstonerdev.io");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.ssl.trust", "redstonerdev.io");

        session = Session.getInstance(props, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
        Logger.getLogger("Email Client").log(Level.INFO,"Init Complete.");
    }

    public static void sendEmail(String to, String subject, String preset, HashMap<String,String> replacements){
        try{
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress("noreply@mail.redstonerdev.io"));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            message.setSubject(subject);

            InputStream fis = SpringBootAuthApplication.class.getClassLoader().getResource(preset).openStream();
            String html = new String(fis.readAllBytes());
            fis.close();

            for(String key : replacements.keySet()){
                html = html.replace(key, replacements.get(key));
            }

            message.setContent(html, "text/html; charset=UTF-8");

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Transport.send(message);
                    } catch (MessagingException e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void sendCreateEmail(String to, String code, String user, String displayname){
        HashMap<String,String> replacements = new HashMap<>();
        replacements.put("%code%", code);
        replacements.put("%username%", user);
        replacements.put("%displayname%", displayname);
        replacements.put("%expiry-time%", "15 Minutes");
        replacements.put("%type%","signup");

        sendEmail(to,"🚀 Welcome to redstonerdev.io!","email.html",replacements);
    }

    public static void sendCreateEmail(String to, String code, String user, String displayname, String id){
        HashMap<String,String> replacements = new HashMap<>();
        replacements.put("%code%", code);
        replacements.put("%username%", user);
        replacements.put("%displayname%", displayname);
        replacements.put("%expiry-time%", "15 Minutes");
        replacements.put("%type%","signup");
        replacements.put("%confirm-url%","https://redstonerdev.io/2fa?id=" + id + "&type=signup");

        sendEmail(to,"🚀 Welcome to redstonerdev.io!","email.html",replacements);
    }

    public static void sendLoginEmail(String to, String code, String user, String displayname){
        HashMap<String,String> replacements = new HashMap<>();
        replacements.put("%code%", code);
        replacements.put("%username%", user);
        replacements.put("%displayname%", displayname);
        replacements.put("%expiry-time%", "15 Minutes");
        replacements.put("%type%","login");

        sendEmail(to,"🚀 Welcome to redstonerdev.io!","email.html",replacements);
    }

    public static void sendLoginEmail(String to, String code, String user, String displayname, String id){
        HashMap<String,String> replacements = new HashMap<>();
        replacements.put("%code%", code);
        replacements.put("%username%", user);
        replacements.put("%displayname%", displayname);
        replacements.put("%expiry-time%", "15 Minutes");
        replacements.put("%type%","login");
        replacements.put("%confirm-url%","https://redstonerdev.io/2fa?id=" + id + "&type=login");

        sendEmail(to,"🚀 Welcome to redstonerdev.io!","email.html",replacements);
    }
}
