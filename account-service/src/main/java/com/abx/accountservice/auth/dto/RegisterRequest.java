package com.abx.accountservice.auth.dto;

public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String passwordHash;

    public RegisterRequest() {}

    private RegisterRequest(Builder builder) {
        setFirstname(builder.firstname);
        setLastname(builder.lastname);
        setEmail(builder.email);
        setPasswordHash(builder.passwordHash);
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
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

        private String firstname;
        private String lastname;
        private String email;
        private String passwordHash;

        private Builder() {}

        public static Builder newBuilder() {
            return new Builder();
        }

        public Builder withFirstname(String val) {
            firstname = val;
            return this;
        }

        public Builder withLastname(String val) {
            lastname = val;
            return this;
        }

        public Builder withEmail(String val) {
            email = val;
            return this;
        }

        public Builder withPasswordHash(String val) {
            passwordHash = val;
            return this;
        }

        public RegisterRequest build() {
            return new RegisterRequest(this);
        }
    }
}
