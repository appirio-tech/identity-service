package com.appirio.tech.core.service.identity.representation;


public enum EmailType {

	PRIMARY(1, "primary"),
	
	SECONDARY(2, "secondary"),
	
	UNKNOWN(0, null);
	
	public final int id;
	
	public final String label;
	
	private EmailType(int id, String label) {
		this.id = id;
		this.label = label!=null ? label : name().toLowerCase();
	}
	
	public static EmailType getById(int id) {
		EmailType[] items = EmailType.class.getEnumConstants();
		for(int i=0; i<items.length; i++) {
			if(items[i].id == id)
				return items[i];
		}
		return UNKNOWN;
	}
	
	public static EmailType getByLabel(String label) {
		if(label==null)
			throw new IllegalArgumentException("label must be specified.");
		EmailType[] items = EmailType.class.getEnumConstants();
		for(int i=0; i<items.length; i++) {
			if(label.equals(items[i].label))
				return items[i];
		}
		return UNKNOWN;
	}
}
