package me.redstoner2019.springbootauth.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface UserJpaRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
    User findByUuid(long uuid);
    User findByEmail(String email);
}
