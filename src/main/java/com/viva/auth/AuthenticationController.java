package com.viva.auth;

import com.viva.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@CrossOrigin(origins = "http://localhost:3000")
@RequiredArgsConstructor
public class AuthenticationController {

    private AuthenticationService service;
    private JavaMailSender javaMailSender;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        return  ResponseEntity.ok(service.register(request));
    }
    @PutMapping("/verify-account")
    public ResponseEntity<String> verifyAccount(
            @RequestParam String email, @RequestParam String otp){
        return   ResponseEntity.ok(service.verifyAccount(email , otp));
    }
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return  ResponseEntity.ok(service.authenticate(request));
    }
    @PostMapping("/regenerate-otp")
    public ResponseEntity<String> regenerateOtp(@RequestBody EmailRequest request) {
        try {
            String email = request.getEmail();
            String generatedOtp = request.getGeneratedOtp();
            String response = service.regenerateOtp(email , generatedOtp);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }


}