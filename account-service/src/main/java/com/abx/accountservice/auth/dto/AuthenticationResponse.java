package com.abx.accountservice.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthenticationResponse {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    public AuthenticationResponse() {}

    private AuthenticationResponse(Builder builder) {
        setAccessToken(builder.accessToken);
        setRefreshToken(builder.refreshToken);
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public static final class Builder {

        private String accessToken;
        private String refreshToken;

        private Builder() {}

        public static Builder newBuilder() {
            return new Builder();
        }

        public Builder withAccessToken(String val) {
            accessToken = val;
            return this;
        }

        public Builder withRefreshToken(String val) {
            refreshToken = val;
            return this;
        }

        public AuthenticationResponse build() {
            return new AuthenticationResponse(this);
        }
    }
}
