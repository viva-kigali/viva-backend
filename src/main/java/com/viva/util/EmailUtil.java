package com.viva.util;

import com.viva.user.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

@Component
public class EmailUtil {
    @Autowired
    private JavaMailSender javaMailSender;
    @Value("${spring.mail.username}")
    private String sender;
    private static final Logger log = LoggerFactory.getLogger(EmailUtil.class);

    public void sendOtpEmail(String email, String firstName, String otp) throws MessagingException {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            log.info("Sender: {}", sender);
            System.out.println(sender);
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
            mimeMessageHelper.setFrom(sender);
            mimeMessageHelper.setTo(email);
            mimeMessageHelper.setSubject("Verify your account");

            String emailContent = String.format("""
            <div>
                <p>Dear <strong>%s</strong>,</p>
                <p>Here is your verification code for <strong>Appointment</strong>: <strong>%s</strong></p>
                <p>Click the link below to continue verification:</p>
                <a href="http://localhost:8080/verify-account?email=%s&otp=%s" target="_blank">Verify Account</a>
            </div>
        """, firstName, otp, email, otp);

            mimeMessageHelper.setText(emailContent, true); // Specify true for isHtml
            javaMailSender.send(mimeMessage);
        } catch (MessagingException e) {
            log.error("Failed to send email", e);
        } catch (Exception e) {
            log.error("Unexpected error while sending email", e);
        }
    }


}
