package com.example.demo.jwt;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<token, Integer> {

    @Query(value = """
      select t from token t inner join UserEntity u\s
      on t.userEntity.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
    List<token> findAllValidTokenByUser(Integer id);

    Optional<token> findByToken(String token);
}
