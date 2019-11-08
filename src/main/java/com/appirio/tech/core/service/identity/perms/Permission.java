package com.appirio.tech.core.service.identity.perms;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Permission {
	public enum EffectType {
		ALLOW, DENY
	}

	private EffectType effect;
	private List<String> actions;
	
	public Permission() {
		this.effect = EffectType.ALLOW;
	}
	
	public Permission(EffectType effect, List<String> actions) {
		this.effect = effect;
		this.actions = actions;
	}

	public EffectType getEffect() {
		return effect;
	}

	public void setEffect(EffectType effect) {
		this.effect = effect;
	}

	public List<String> getActions() {
		return actions;
	}

	public void setActions(List<String> actions) {
		this.actions = actions;
	}
	
	public Permission withActions(String... actions) {
		if (this.actions == null) {
			this.actions = new ArrayList<>(actions.length);
		}
		this.actions.addAll(Arrays.asList(actions));
		return this;
	}

}
