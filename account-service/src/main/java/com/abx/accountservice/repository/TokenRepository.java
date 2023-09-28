package com.abx.accountservice.repository;

import com.abx.accountservice.model.TokenEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TokenRepository extends JpaRepository<TokenEntity, UUID> {

    @Query(
            value =
                    """
      SELECT * FROM account_service.token AS t INNER JOIN account_service.users AS u
      on t.user_id = u.id
      where u.id = :id and (t.expired = false or t.revoked = false)
      """,
            nativeQuery = true)
    List<TokenEntity> findAllValidTokenByUser(UUID id);

    Optional<TokenEntity> findByToken(String token);
}
