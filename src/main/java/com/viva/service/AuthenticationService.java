package com.viva.service;

import com.viva.auth.AuthenticationRequest;
import com.viva.auth.AuthenticationResponse;
import com.viva.auth.RegisterRequest;
import com.viva.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);

    String verifyAccount(String email, String otp);

    AuthenticationResponse authenticate(AuthenticationRequest request);

    String regenerateOtp(String email, String enteredOtp);

    void revokeAllUserToken(User user);

    void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException;
}