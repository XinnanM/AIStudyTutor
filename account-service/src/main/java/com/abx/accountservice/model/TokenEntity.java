package com.abx.accountservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.UUID;
import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(name = "token", schema = "account_service")
public class TokenEntity {

    public TokenEntity() {}

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    @Column(unique = true)
    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType = TokenType.BEARER;

    private boolean revoked;

    private boolean expired;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private UserEntity user;

    private TokenEntity(Builder builder) {
        setId(builder.id);
        setToken(builder.token);
        setTokenType(builder.tokenType);
        setRevoked(builder.revoked);
        setExpired(builder.expired);
        setUser(builder.user);
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public TokenType getTokenType() {
        return tokenType;
    }

    public void setTokenType(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public boolean isExpired() {
        return expired;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    public UserEntity getUser() {
        return user;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public static final class Builder {

        private UUID id;
        private String token;
        private TokenType tokenType;
        private boolean revoked;
        private boolean expired;
        private UserEntity user;

        private Builder() {}

        public static Builder newBuilder() {
            return new Builder();
        }

        public Builder withId(UUID val) {
            id = val;
            return this;
        }

        public Builder withToken(String val) {
            token = val;
            return this;
        }

        public Builder withTokenType(TokenType val) {
            tokenType = val;
            return this;
        }

        public Builder withRevoked(boolean val) {
            revoked = val;
            return this;
        }

        public Builder withExpired(boolean val) {
            expired = val;
            return this;
        }

        public Builder withUser(UserEntity val) {
            user = val;
            return this;
        }

        public TokenEntity build() {
            return new TokenEntity(this);
        }
    }
}
