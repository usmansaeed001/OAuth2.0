package com.raze.repository;

import com.raze.entity.OAuth2ClientRole;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author: Raze
 */
public interface OAuth2ClientRoleRepository extends JpaRepository<OAuth2ClientRole, Long> {

    OAuth2ClientRole findByClientRegistrationIdAndRoleCode(String clientRegistrationId, String roleCode);
}
