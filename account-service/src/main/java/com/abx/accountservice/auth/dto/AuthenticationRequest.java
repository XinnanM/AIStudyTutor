package com.abx.accountservice.auth.dto;

public class AuthenticationRequest {

    private String email;
    private String passwordHash;

    public AuthenticationRequest() {}

    private AuthenticationRequest(Builder builder) {
        setEmail(builder.email);
        setPasswordHash(builder.passwordHash);
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public static final class Builder {

        private String email;
        private String passwordHash;

        private Builder() {}

        public static Builder newBuilder() {
            return new Builder();
        }

        public Builder withEmail(String val) {
            email = val;
            return this;
        }

        public Builder withPasswordHash(String val) {
            passwordHash = val;
            return this;
        }

        public AuthenticationRequest build() {
            return new AuthenticationRequest(this);
        }
    }
}
