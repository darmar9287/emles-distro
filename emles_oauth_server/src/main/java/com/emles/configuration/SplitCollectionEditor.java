package com.emles.configuration;

import org.springframework.beans.propertyeditors.CustomCollectionEditor;

import java.util.Collection;

/**
 * Class used for splitting custom collection.
 * 
 * @author Dariusz Kulig
 *
 */
public class SplitCollectionEditor extends CustomCollectionEditor {

	/**
	 * collectionType - collection to be splitted.
	 */
	@SuppressWarnings("rawtypes")
	private Class<? extends Collection> collectionType;

	/**
	 * splitRegex - regex used to split collection.
	 */
	private String splitRegex;

	/**
	 * Constructor of this class.
	 * 
	 * @param colType - collection type.
	 * @param regex   - split regex field.
	 */
	@SuppressWarnings("rawtypes")
	public SplitCollectionEditor(Class<? extends Collection> colType, String regex) {
		super(colType, true);
		this.collectionType = colType;
		this.splitRegex = regex;
	}

	@Override
	public final void setAsText(String text) throws IllegalArgumentException {
		if (text == null || text.isEmpty()) {
			super.setValue(super.createCollection(this.collectionType, 0));
		} else {
			super.setValue(text.split(splitRegex));
		}
	}
}
