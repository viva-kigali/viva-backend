package com.viva.impl;

import com.viva.auth.AuthenticationController;
import com.viva.auth.AuthenticationRequest;
import com.viva.auth.AuthenticationResponse;
import com.viva.auth.RegisterRequest;
import com.viva.service.AuthenticationService;
import com.viva.token.Token;
import com.viva.user.Role;
import com.viva.user.User;
import com.viva.util.EmailUtil;
import com.viva.util.OtpUtil;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.viva.repositories.*;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
public class AuthenticationServiceImp implements AuthenticationService {
    private UserRepository repository;
    private OtpUtil otpUtil;
    private  PasswordEncoder passwordEncoder;
    private JwtServiceImp jwtService;
    private AuthenticationManager authenticationManager;
    private TokenRepository tokenRepository;
    private EmailUtil emailUtil;
    private static  final  Logger log = LoggerFactory.getLogger(AuthenticationController.class);

    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        String otp = otpUtil.generateOtp();
        String hashedPassword = passwordEncoder.encode(request.getPassword());
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(hashedPassword)
                .otp(otp)
                .otpGeneratedTime(LocalDateTime.now())
                .role(Role.valueOf("USER"))
                .build();

        var savedUser = repository.save(user);
        System.out.println(savedUser);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser , jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .user(user)
                .build();


    }
    @Override
    public String verifyAccount(String email, String otp){
        User user = repository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found with this email: "+ email));
        if(user.getOtp().equals(otp) && Duration.between(user.getOtpGeneratedTime(),
                LocalDateTime.now()).getSeconds() < ( 1 * 60)){
            repository.save(user);
            return "OTP verified you can login";
        }
        return  "OTP regenerate otp and try again";
    }
    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
//        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
//                request.getEmail(),
//                request.getPassword()
//        ));
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));
        if(!passwordEncoder.matches(request.getPassword(),user.getPassword())){
            throw  new RuntimeException("Invalid email or password");
        }
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .user(user)
                .build();
    }

    @Override
    public String regenerateOtp(String email,String enteredOtp) {
        try {
            User user = repository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found with this email: " + email));

            String generatedOtp = otpUtil.generateOtp();
            emailUtil.sendOtpEmail(email, user.getFirstname(), generatedOtp);

            if(enteredOtp!=null && !enteredOtp.equals(generatedOtp)){
                throw new RuntimeException("Incorrect OTP. Please enter the correct OTP.");
            }

            user.setOtp(generatedOtp);
            user.setOtpGeneratedTime(LocalDateTime.now());
            repository.save(user);

            return "Email sent to " + email + ". Please verify your account within 1 minute.";
        } catch (MessagingException e) {
            log.error("Failed to send OTP email", e);
            throw new RuntimeException("Unable to send OTP. Please try again.");
        } catch (Exception e) {
            log.error("Unexpected error during OTP generation and email sending", e);
            throw new RuntimeException("An unexpected error occurred. Please try again.");
        }
    }





    private void  saveUserToken(User user , String jwtToken){
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }
    public void revokeAllUserToken(User user) {
        var validuserToken = tokenRepository.findALlValidTokenUser(user.getId());
        if(validuserToken.isEmpty())
            return;
        validuserToken.forEach((token) -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
    }
    @Override
    public void  refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if(authHeader == null || authHeader.startsWith("Bearer ")){
            refreshToken = authHeader.substring(7);
            userEmail = jwtService.extractUsername(refreshToken);
            if(userEmail !=null){
                var user = this.repository.findByEmail(userEmail)
                        .orElseThrow();
                if(jwtService.isTokenValid(refreshToken,user)){
                    var accessToken = jwtService.generateToken(user);
                    revokeAllUserToken(user);
                    saveUserToken(user , accessToken);
                    var authResponse =  AuthenticationResponse.builder()
                            .accessToken(refreshToken)
                            .refreshToken(refreshToken)
                            .build();
                }
            }

        }
    }



}
