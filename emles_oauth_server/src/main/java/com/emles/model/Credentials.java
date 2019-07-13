package com.emles.model;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.persistence.Version;
import javax.validation.constraints.NotEmpty;
import java.io.Serializable;
import java.util.List;

/**
 * Credentials model.
 * @author Dariusz Kulig
 *
 */
@Entity
@Table(name = "credentials")
public class Credentials implements Serializable {

    /**
     * serialVersionUID - unique value needed for serialization.
     */
    private static final long serialVersionUID = 1L;

    /**
    * id - credential id field in table.
    */
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    /**
     * version - version of this object.
    */
    @Version
    private Integer version;

    /**
     * name - user login name.
     */
    @NotEmpty
    private String name;

    /**
     * password - field containing hash of user.
     */
    @NotEmpty
    private String password;

    /**
     * authorities - list of granted authorities for a given user.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    private List<Authority> authorities;

    /**
     * enabled - check if user can sign in.
     */
    private boolean enabled;

    /**
     * Getter for credential id.
     * @return id of credential
     */
    public Long getId() {
        return id;
    }

    /**
     * Setter for credential id.
     * @param credId - id of credential
     */
    public void setId(Long credId) {
        this.id = credId;
    }

    /**
     * Getter for version field.
     * @return version field.
     */
    public Integer getVersion() {
        return version;
    }

    /**
     * Setter for version field.
     * @param v - version of serialized object.
     */
    public void setVersion(Integer v) {
        this.version = v;
    }

    /**
     * Getter for name field.
     * @return name of user who tries to log in.
     */
    public String getName() {
        return name;
    }

    /**
     * Setter for name field.
     * @param n - field name in credentials table.
     */
    public void setName(String n) {
        this.name = n;
    }

    /**
     * Getter for password field.
     * @return password string value
     */
    public String getPassword() {
        return password;
    }

    /**
     * Setter for password field.
     * @param pass - password string value.
     */
    public void setPassword(String pass) {
        this.password = pass;
    }

    /**
     * Getter for authorities.
     * @return list of associated with this model authorities.
     */
    public List<Authority> getAuthorities() {
        return authorities;
    }

    /**
     * Setter for authorities.
     * @param auths - authorities list
     */
    public void setAuthorities(List<Authority> auths) {
        this.authorities = auths;
    }

    /**
     * Getter for enabled field.
     * @return enabled field.
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Setter for enabled field.
     * @param en - boolean value for enabled user.
     */
    public void setEnabled(boolean en) {
        this.enabled = en;
    }
}
