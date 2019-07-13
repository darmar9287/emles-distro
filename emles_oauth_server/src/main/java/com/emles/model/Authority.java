
package com.emles.model;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.io.Serializable;

/**
 * Authority model used to distinguish user roles.
 *
 * @author Dariusz Kulig
 * @version 1.1
 */
@Entity
public final class Authority implements GrantedAuthority, Serializable {
    private static final long serialVersionUID = 1L;

    /** authority_id field in DB.*/
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    /** authority field in DB.*/
    private String authority;

    /**
     * Getter for id field.
     * @return id of authority object
     * */
    public Long getId() {
        return id;
    }

    /**
     * Setter for id field.
     * @param authorityId - id of authority object
     */
    public void setId(final Long authorityId) {
        this.id = authorityId;
    }

    /**
     * Getter for authority name.
     * @return authority name
     */
    @Override
    public String getAuthority() {
        return authority;
    }

    /**
     * Setter for authority name.
     * @param auth name
     */
    public void setAuthority(final String auth) {
        this.authority = auth;
    }
}
