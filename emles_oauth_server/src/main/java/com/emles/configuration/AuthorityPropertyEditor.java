package com.emles.configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.awt.Component;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.beans.PropertyChangeListener;
import java.beans.PropertyEditor;

/**
 * Class for formatting granted authority values.
 * @author dariusz
 *
 */
public class AuthorityPropertyEditor implements PropertyEditor {

    /**
     * grantedAuthority - user authrities.
     */
    private GrantedAuthority grantedAuthority;

    @Override
    public final void setValue(final Object value) {
        this.grantedAuthority = (GrantedAuthority) value;
    }

    @Override
    public final Object getValue() {
        return grantedAuthority;
    }

    @Override
    public final boolean isPaintable() {
        return false;
    }

    @Override
    public void paintValue(final Graphics gfx, final Rectangle box) {

    }

    @Override
    public final String getJavaInitializationString() {
        return null;
    }

    @Override
    public final String getAsText() {
        return grantedAuthority.getAuthority();
    }

    @Override
    public final void setAsText(final String text)
        throws IllegalArgumentException {
        if (text != null && !text.isEmpty()) {
            this.grantedAuthority = new SimpleGrantedAuthority(text);
        }
    }

    @Override
    public final String[] getTags() {
        return new String[0];
    }

    @Override
    public final Component getCustomEditor() {
        return null;
    }

    @Override
    public final boolean supportsCustomEditor() {
        return false;
    }

    @Override
    public void addPropertyChangeListener(
        final PropertyChangeListener listener) {
    }

    @Override
    public void removePropertyChangeListener(
        final PropertyChangeListener listener) {
    }
}
