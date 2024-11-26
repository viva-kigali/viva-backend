package com.viva.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EmailRequest {
    private String email;
    private String generatedOtp;

    public String getGeneratedOtp() {
        this.generatedOtp = generatedOtp;
        return null;
    }

    public String getEmail() {
        this.email = email;
        return null;
    }
}
