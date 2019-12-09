package com.appirio.tech.core.service.identity.dao;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;
import org.reflections.util.Utils;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.document.AttributeUpdate;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.PutItemOutcome;
import com.amazonaws.services.dynamodbv2.document.UpdateItemOutcome;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.amazonaws.services.dynamodbv2.model.ReturnValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ExternalAccountDAO {

	private static final Logger logger = Logger.getLogger(ExternalAccountDAO.class);
	
	protected DynamoDB db;
	
	protected ObjectMapper objectMapper;
	
	public static final String TABLE_EXTERNAL_ACCOUNTS = "Externals.Accounts";
	
	public ExternalAccountDAO(AmazonDynamoDB db, ObjectMapper objectMapper) {
		this.db = createDynamoDB(db);
		this.objectMapper = objectMapper;
	}

	public ExternalAccount put(ExternalAccount externalAccount) {
		if(externalAccount==null)
			throw new IllegalArgumentException("externalAccount must be specifeid.");
		if(Utils.isEmpty(externalAccount.getUserId()))
			throw new IllegalArgumentException("userId must be specifeid.");
		if(Utils.isEmpty(externalAccount.getAccountType()))
			throw new IllegalArgumentException("accountType must be specifeid.");
		
		PutItemOutcome outcome =
			db.getTable(TABLE_EXTERNAL_ACCOUNTS)
				.putItem(createPutItemSpecWith(externalAccount));
		
		logger.debug(String.format("put(%s:%s) result: %s", externalAccount.getUserId(), externalAccount.getAccountType(), outcome==null ? "null" : outcome.getPutItemResult()));
		
		return externalAccount;
	}
	
	public ExternalAccount delete(ExternalAccount externalAccount) {
		if(externalAccount==null)
			throw new IllegalArgumentException("externalAccount must be specifeid.");
		if(Utils.isEmpty(externalAccount.getUserId()))
			throw new IllegalArgumentException("userId must be specifeid.");
		if(Utils.isEmpty(externalAccount.getAccountType()))
			throw new IllegalArgumentException("accountType must be specifeid.");

		UpdateItemOutcome outcome =
			db.getTable(TABLE_EXTERNAL_ACCOUNTS)
				.updateItem(createUpdateItemSpecToDeleteWith(externalAccount));
		
		logger.debug(String.format("delete(%s:%s) result: %s", externalAccount.getUserId(), externalAccount.getAccountType(), outcome==null ? "null" : outcome.getUpdateItemResult()));

		return externalAccount;
	}
	
	protected DynamoDB createDynamoDB(AmazonDynamoDB db) {
		return new DynamoDB(db);
	}
	
	protected PutItemSpec createPutItemSpecWith(ExternalAccount externalAccount) {
		if(externalAccount==null)
			throw new IllegalArgumentException("externalAccount must be specifeid.");
		
		long ts = System.currentTimeMillis();
		externalAccount.setCreatedAt(ts);
		externalAccount.setUpdatedAt(ts);
		
		return new PutItemSpec()
			.withReturnValues(ReturnValue.ALL_OLD)
			.withItem(new Item()
		    	.withPrimaryKey("userId", emptyToNull(externalAccount.getUserId()),
		    					"accountType", emptyToNull(externalAccount.getAccountType()))
		    	.withBoolean("hasErrored", externalAccount.hasErrored())
		    	.withBoolean("isDeleted", externalAccount.isDeleted())
		    	.withLong("createdAt", externalAccount.getCreatedAt())
		    	.withLong("updatedAt", externalAccount.getUpdatedAt())
		    	.withLong("synchronizedAt", externalAccount.getSynchronizedAt())
		    	.withJSON("params", serialize(emptyToNull(externalAccount.getParams()))));
	}

	protected UpdateItemSpec createUpdateItemSpecToDeleteWith(ExternalAccount externalAccount) {
		if(externalAccount==null)
			throw new IllegalArgumentException("externalAccount must be specifeid.");
		
		externalAccount.setDeleted(true);
		externalAccount.setUpdatedAt(System.currentTimeMillis());

		return new UpdateItemSpec()
			.withReturnValues(ReturnValue.ALL_NEW)
		    .withPrimaryKey("userId", emptyToNull(externalAccount.getUserId()),
		    				"accountType", emptyToNull(externalAccount.getAccountType()))
		    .withAttributeUpdate(
		    	new AttributeUpdate("isDeleted").put(externalAccount.isDeleted()),
		    	new AttributeUpdate("updatedAt").put(externalAccount.getUpdatedAt()));
	}
	
	protected String emptyToNull(String val) {
		return "".equals(val) ? null : val;
	}
	
	protected Map<String, String> emptyToNull(Map<String, String> map) {
		if(map==null || map.size()==0)
			return map;
		Map<String, String> tmp = new HashMap<String, String>(map.size());
		for(Iterator<String> iter=map.keySet().iterator(); iter.hasNext(); ) {
			String key = iter.next();
			tmp.put(key, emptyToNull(map.get(key)));
		}
		return tmp;
	}
	
	protected String serialize(Object obj) {
		if(obj==null)
			return "{}";
		try {
			return this.objectMapper.writeValueAsString(obj);
		} catch (JsonProcessingException e) {
			throw new RuntimeException("Failed to jsonize object.", e); //TODO
		}
	}
	
	public static class ExternalAccount {
		
		private String userId;
		private String accountType;
		private Map<String,String> params;
		private boolean hasErrored;
		private boolean isDeleted;
		private long createdAt;
		private long updatedAt;
		private long synchronizedAt;
		public String getUserId() {
			return userId;
		}
		public void setUserId(String userId) {
			this.userId = userId;
		}
		public String getAccountType() {
			return accountType;
		}
		public void setAccountType(String accountType) {
			this.accountType = accountType;
		}
		public Map<String,String> getParams() {
			return params;
		}
		public void setParams(Map<String,String> params) {
			this.params = params;
		}
		public boolean hasErrored() {
			return hasErrored;
		}
		public void setHasErrored(boolean hasErrored) {
			this.hasErrored = hasErrored;
		}
		public boolean isDeleted() {
			return isDeleted;
		}
		public void setDeleted(boolean isDeleted) {
			this.isDeleted = isDeleted;
		}
		public long getCreatedAt() {
			return createdAt;
		}
		public void setCreatedAt(long createdAt) {
			this.createdAt = createdAt;
		}
		public long getUpdatedAt() {
			return updatedAt;
		}
		public void setUpdatedAt(long updatedAt) {
			this.updatedAt = updatedAt;
		}
		public long getSynchronizedAt() {
			return synchronizedAt;
		}
		public void setSynchronizedAt(long synchronizedAt) {
			this.synchronizedAt = synchronizedAt;
		}
	}
}
