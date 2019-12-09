package com.appirio.tech.core.service.identity.perms;

public class PermissionRule {

	public enum RuleType {
		EXPR, ID, APPLY_TO_ALL, CUSTOM
	}

	private RuleType ruleType;
	private String rule;
	
	public PermissionRule() {
		
	}
	
	public PermissionRule(RuleType ruleType, String rule) {
		this.ruleType = ruleType;
		this.rule = rule;
	}

	public RuleType getRuleType() {
		return ruleType;
	}

	public void setRuleType(RuleType ruleType) {
		this.ruleType = ruleType;
	}

	public PermissionRule withRuleType(RuleType ruleType) {
		this.ruleType = ruleType;
		return this;
	}

	public String getRule() {
		return rule;
	}

	public void setRule(String rule) {
		this.rule = rule;
	}

	public PermissionRule withRule(String rule) {
		this.rule = rule;
		return this;
	}
}
