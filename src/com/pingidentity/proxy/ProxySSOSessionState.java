package com.pingidentity.proxy;

import java.io.Serializable;
import java.util.Date;

import org.json.simple.JSONObject;

/**
 * state (i.e. JSON identity attributes + timestamp that is stored in the session
 */
public class ProxySSOSessionState implements Serializable {
	  
	private static final long serialVersionUID = 7116471291112771141L;
	
	private JSONObject jsonObject = null;
	private Date timeStamp = null;
	public ProxySSOSessionState(JSONObject json) {
		this.jsonObject = json;
		this.timeStamp = new Date();
	}

	public JSONObject getJSONObject() {
		return this.jsonObject;
	}

	public Date getTimestamp() {
		return this.timeStamp;
	}
}
