package com.appirio.tech.core.service.identity.util;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.HttpURLConnection;

import org.junit.Test;

import com.appirio.tech.core.service.identity.util.HttpUtil.Request;
import com.appirio.tech.core.service.identity.util.HttpUtil.Response;

public class HttpUtilTest {

	@Test
	public void testRequest() throws Exception {
		
		// testee with mocking internalExecute()
		Request testee = spy(new Request("http://dummy-host", "GET"));
		Response resp = new Response();
		resp.setStatusCode(HttpURLConnection.HTTP_OK);
		resp.setMessage("OK");
		resp.setText("DUMMY-RESP-BODY");
		doReturn(resp).when(testee).internalExecute();
		
		// test
		Response result = testee
							.header("h1", "h1value")
							.param("p1", "p1value")
							.retry(0)
							.execute();
		// verify result
		assertNotNull(result);
		assertEquals(resp, result);
		// verify mock
		verify(testee, times(1)).internalExecute();
	}
	
	
	@Test
	public void testRequest_RetryingWhenNetworkErrorOccurred() throws Exception {
		
		// testee with mocking internalExecute()
		Request testee = spy(createRequestForTest());
		Response resp = new Response();
		resp.setStatusCode(HttpURLConnection.HTTP_OK);
		resp.setMessage("OK");
		resp.setText("DUMMY-RESP-BODY");
		Exception nwError = new IOException("Network Error");
		when(testee.internalExecute())
			.thenThrow(nwError) // 1st time : error
			.thenReturn(resp);  // 2nd time : recovered
		
		// test
		Response result = testee.retry(1).execute();
		
		// verify result
		assertNotNull(result);
		assertEquals(resp, result);
		// verify mock
		verify(testee, times(2)).internalExecute(); // invoked 2 times.
	}

	@Test
	public void testRequest_RetryingWhenGetting50x() throws Exception {
		
		// testee with mocking internalExecute()
		Request testee = spy(createRequestForTest());
		Response resp = new Response();
		resp.setStatusCode(HttpURLConnection.HTTP_OK);
		resp.setMessage("OK");
		resp.setText("DUMMY-RESP-BODY");
		
		Response resp500 = new Response();
		resp500.setStatusCode(HttpURLConnection.HTTP_INTERNAL_ERROR);

		when(testee.internalExecute())
			.thenReturn(resp500) // 1st time : error
			.thenReturn(resp);   // 2nd time : recovered
		
		// test
		Response result = testee.retry(1).execute();
		
		// verify result
		assertNotNull(result);
		assertEquals(resp, result);
		// verify mock
		verify(testee, times(2)).internalExecute(); // invoked 2 times.
	}
	
	@Test
	public void testRequest_ErrorsOccurredOverRetryLimit1() throws Exception {
		
		// testee with mocking internalExecute()
		Request testee = spy(createRequestForTest());
		Response resp500 = new Response();
		resp500.setStatusCode(HttpURLConnection.HTTP_INTERNAL_ERROR); //500
		Response resp503 = new Response();
		resp503.setStatusCode(HttpURLConnection.HTTP_UNAVAILABLE); // 503

		Exception nwError = new IOException("Network Error");
		when(testee.internalExecute())
			.thenReturn(resp500) // 1st time : error
			.thenThrow(nwError)  // 2nd time : error
			.thenReturn(resp503);// 3rd time : error
		
		// test
		Response result = testee.retry(2).execute();
		
		// verify result
		assertNotNull(result);
		assertEquals(resp503, result);
		// verify mock
		verify(testee, times(3)).internalExecute(); // invoked 3 times.
	}
	
	@Test
	public void testRequest_ErrorsOccurredOverRetryLimit2() throws Exception {
		
		// testee with mocking internalExecute()
		Request testee = spy(createRequestForTest());
		Response resp500 = new Response();
		resp500.setStatusCode(HttpURLConnection.HTTP_INTERNAL_ERROR); //500
		resp500.setMessage("Server Error!");
		Exception nwError1 = new IOException("Network Error1");
		Exception nwError2 = new IOException("Network Error2");
		
		when(testee.internalExecute())
			.thenReturn(resp500)  // 1st time : error
			.thenThrow(nwError1)  // 2nd time : error
			.thenThrow(nwError2); // 3rd time : error
		
		// test
		try {
			testee.retry(2).execute();
			fail("The exception should be thrown in the previous step.");
		} catch (Exception e) {
			assertEquals(nwError2, e); // The last exception should be thrown. 
		}
		
		// verify mock
		verify(testee, times(3)).internalExecute(); // invoked 3 times.
	}

	// creating Request with dummy impl on internalExecute()
	protected Request createRequestForTest() {
		return new Request("http://localhost", "GET") {
			@Override protected Response internalExecute() throws Exception {
				return null; //dummy - to suppress error in "when(testee.internalExecute())"
			}};
	}
	
	// TODO: test for internalExecute()
}
