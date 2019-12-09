package com.appirio.tech.core.service.identity.dao;

import static org.junit.Assert.*;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.document.AttributeUpdate;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.KeyAttribute;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;
import com.amazonaws.services.dynamodbv2.document.spec.UpdateItemSpec;
import com.appirio.tech.core.service.identity.dao.ExternalAccountDAO.ExternalAccount;
import com.fasterxml.jackson.databind.ObjectMapper;



public class ExternalAccountDAOTest {

	@Test
	public void testPut() throws Exception {
		// data
		ExternalAccount externalAccount = createExternalAccount();
		
		// mock
		final DynamoDB dynamoDb = mock(DynamoDB.class);
		Table externAccountTable = mock(Table.class);
		when(dynamoDb.getTable(ExternalAccountDAO.TABLE_EXTERNAL_ACCOUNTS)).thenReturn(externAccountTable);
		
		// testee
		ExternalAccountDAO externalAccountDAO = createExternalAccountDAO(dynamoDb, new ObjectMapper());
		
		// test
		ExternalAccount result = externalAccountDAO.put(externalAccount);
		
		// verify
		assertNotNull(result);
		assertNotNull(result.getCreatedAt());
		assertNotNull(result.getUpdatedAt());
		assertEquals(externalAccount.getUserId(), result.getUserId());
		assertEquals(externalAccount.getAccountType(), result.getAccountType());
		assertEquals(externalAccount.getSynchronizedAt(), result.getSynchronizedAt());
		assertEquals(externalAccount.isDeleted(), result.isDeleted());
		assertEquals(externalAccount.hasErrored(), result.hasErrored());
		assertEquals(externalAccount.getParams(), result.getParams());
		
		verify(dynamoDb).getTable(ExternalAccountDAO.TABLE_EXTERNAL_ACCOUNTS);
		verify(externAccountTable).putItem(any(PutItemSpec.class));
	}

	@SuppressWarnings("rawtypes")
	@Test
	public void testCreatePutItemSpecWith() throws Exception {
		// data
		ExternalAccount externalAccount = createExternalAccount();
		externalAccount.getParams().put("p1", "v1");
		
		// mock
		final DynamoDB dynamoDb = mock(DynamoDB.class);
		
		// testee
		ExternalAccountDAO externalAccountDAO = createExternalAccountDAO(dynamoDb, new ObjectMapper());
		
		// test
		PutItemSpec result = externalAccountDAO.createPutItemSpecWith(externalAccount);
		
		assertNotNull(result);
		
		Item itemInResult = result.getItem();
		assertNotNull(itemInResult);
		
		assertEquals(itemInResult.getString("userId"),
				externalAccount.getUserId());
		assertEquals(itemInResult.getString("accountType"),
				externalAccount.getAccountType());
		assertEquals(itemInResult.getBoolean("hasErrored"),
				externalAccount.hasErrored());
		assertEquals(itemInResult.getBoolean("isDeleted"),
				externalAccount.isDeleted());
		assertEquals(itemInResult.getLong("synchronizedAt"),
				externalAccount.getSynchronizedAt());
		assertEquals(itemInResult.getLong("createdAt"),
				externalAccount.getCreatedAt());
		assertEquals(itemInResult.getLong("updatedAt"),
				externalAccount.getUpdatedAt());
		
		Object paramInResult = itemInResult.get("params");
		assertNotNull(paramInResult);
		assertTrue(paramInResult instanceof Map);
		assertEquals(((Map)paramInResult).get("p1"), externalAccount.getParams().get("p1"));
	}

	@Test
	public void testDelete() throws Exception {
		// data
		ExternalAccount externalAccount = createExternalAccount();
		externalAccount.setDeleted(false);
		long createdAt = externalAccount.getCreatedAt();
		long updatedAt = externalAccount.getUpdatedAt();
		
		// mock
		final DynamoDB dynamoDb = mock(DynamoDB.class);
		Table externAccountTable = mock(Table.class);
		when(dynamoDb.getTable(ExternalAccountDAO.TABLE_EXTERNAL_ACCOUNTS)).thenReturn(externAccountTable);
		
		// testee
		ExternalAccountDAO externalAccountDAO = createExternalAccountDAO(dynamoDb, new ObjectMapper());
		
		// test
		ExternalAccount result = externalAccountDAO.delete(externalAccount);
		
		// verify
		assertNotNull(result);
		
		// updatedAt: should be updated
		assertTrue(updatedAt < result.getUpdatedAt());
		assertEquals(result.getUpdatedAt(), result.getUpdatedAt());
		
		// isDeleted: should be true
		assertTrue(result.isDeleted());
		assertEquals(externalAccount.isDeleted(), result.isDeleted());

		// other field should not be changed
		assertEquals(createdAt, result.getCreatedAt());
		assertEquals(externalAccount.getCreatedAt(), result.getCreatedAt());
		assertEquals(externalAccount.getUserId(), result.getUserId());
		assertEquals(externalAccount.getAccountType(), result.getAccountType());
		assertEquals(externalAccount.getSynchronizedAt(), result.getSynchronizedAt());
		assertEquals(externalAccount.hasErrored(), result.hasErrored());
		assertEquals(externalAccount.getParams(), result.getParams());
		
		verify(dynamoDb).getTable(ExternalAccountDAO.TABLE_EXTERNAL_ACCOUNTS);
		verify(externAccountTable).updateItem(any(UpdateItemSpec.class));
	}
	
	@Test
	public void testCreateUpdateItemSpecToDeleteWith() throws Exception {
		// data
		ExternalAccount externalAccount = createExternalAccount();
		
		// mock
		final DynamoDB dynamoDb = mock(DynamoDB.class);
		
		// testee
		ExternalAccountDAO externalAccountDAO = createExternalAccountDAO(dynamoDb, new ObjectMapper());
		
		// test
		UpdateItemSpec result = externalAccountDAO.createUpdateItemSpecToDeleteWith(externalAccount);
		
		assertNotNull(result);
		
		// check key
		assertNotNull(result.getKeyComponents());
		Map<String, String> tmpMap = new HashMap<String, String>();
		for(Iterator<KeyAttribute> iter=result.getKeyComponents().iterator(); iter.hasNext(); ) {
			KeyAttribute kattr = iter.next();
			tmpMap.put(kattr.getName(), kattr.getValue().toString());
		}
		assertTrue(tmpMap.containsKey("userId"));
		assertEquals(tmpMap.get("userId"), externalAccount.getUserId());
		assertTrue(tmpMap.containsKey("accountType"));
		assertEquals(tmpMap.get("accountType"), externalAccount.getAccountType());
		
		// check attributes to update
		List<AttributeUpdate> attrUpdatesInResult = result.getAttributeUpdate();
		assertNotNull(attrUpdatesInResult);
		assertEquals(2, attrUpdatesInResult.size());
		Map<String, Object> tmpMap2 = new HashMap<String, Object>();
		for(Iterator<AttributeUpdate> iter=attrUpdatesInResult.iterator(); iter.hasNext(); ) {
			AttributeUpdate attr = iter.next();
			tmpMap2.put(attr.getAttributeName(), attr.getValue());
		}
		assertTrue(tmpMap2.containsKey("isDeleted"));
		assertEquals(true, tmpMap2.get("isDeleted"));
		assertTrue(tmpMap2.containsKey("updatedAt"));
		assertEquals(externalAccount.getUpdatedAt(), tmpMap2.get("updatedAt"));
	}
	
	protected ExternalAccountDAO createExternalAccountDAO(final DynamoDB dynamoDb, ObjectMapper mapper) {
		return new ExternalAccountDAO(null, mapper) {
			@Override protected DynamoDB createDynamoDB(AmazonDynamoDB db) { return dynamoDb; }
		};
	}
	
	protected ExternalAccount createExternalAccount() {
		ExternalAccount externalAccount = new ExternalAccount();
		externalAccount.setAccountType("DUMMY-ACCOUNT-TYPE");
		externalAccount.setUserId("DUMMY-USER-ID");
		externalAccount.setDeleted(false);
		externalAccount.setHasErrored(false);
		externalAccount.setSynchronizedAt(0L);
		externalAccount.setParams(new HashMap<String, String>());
		externalAccount.setCreatedAt(System.currentTimeMillis()-100L);
		externalAccount.setUpdatedAt(System.currentTimeMillis()-100L);
		return externalAccount;
	}
}
