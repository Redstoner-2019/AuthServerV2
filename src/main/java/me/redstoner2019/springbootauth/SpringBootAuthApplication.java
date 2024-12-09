package me.redstoner2019.springbootauth;

import me.redstoner2019.springbootauth.mail.Mail;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringBootAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootAuthApplication.class, args);
        Mail.init();
    }

}
