package com.raze.repository;

import com.raze.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author: Raze
 */
public interface UserRepository extends JpaRepository<User, Long> {

    User findUserByUsername(String username);
}
