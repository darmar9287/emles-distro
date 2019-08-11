package com.emles.model.projection;

import com.emles.model.UserData;

public interface UserSimplified {
	Long getId();
	
	String getName();
	
	UserData getUserData();
}
