package com.pingidentity.proxy;

/***************************************************************************
 * Copyright (C) 2011-2016 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @Version: 4.7
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 *
 **************************************************************************/

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.net.*;

import javax.net.ssl.*;

import java.security.cert.*;

import javax.servlet.ServletException;
import javax.servlet.http.*;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.sourceid.saml20.adapter.state.SessionStateSupport;

public class ProxyServlet extends HttpServlet {

	public class ProxySSOSessionState implements Serializable {

		private static final long serialVersionUID = 7116471291112771141L;

		private JSONObject jsonObject = null;
		private Date created = null;
		private Date lastAccess = null;

		public ProxySSOSessionState(JSONObject json) {
			this.jsonObject = json;
			this.created = new Date();
			this.lastAccess = new Date();
		}

		public JSONObject getJSONObject() {
			return this.jsonObject;
		}

		public boolean isValid(long sessionTimeout, long sessionIdleTimeout) {
			Date now = new Date();
			if (now.after(new Date(this.created.getTime() + sessionTimeout
					* 1000)))
				return false;
			if ((sessionIdleTimeout > 0)
					&& (lastAccess.before(new Date(now.getTime()
							- sessionIdleTimeout * 1000))))
				return false;
			this.lastAccess = now;
			return true;
		}
	}

	private static final long serialVersionUID = 7728776183597697066L;

	static final String proxyVersion = "4.7";

	/**
	 * Execute a REST call to the Reference ID adapter.
	 */
	public JSONObject doREST(String url, Properties p, String type,
			JSONObject jsonRespObj) throws IOException {

		X509TrustManager tm = null;
		HostnameVerifier hv = null;
		SSLSocketFactory socketFactory = null;

		try {

			URL u = new URL(url);
			URLConnection con = null;
			
			if (url.startsWith("https://")) {
				
				if (Boolean.parseBoolean(p.getProperty(
						"ssl.server.certificate.validation", "true")) != true) {
					tm = new X509TrustManager() {
						public void checkClientTrusted(X509Certificate[] x509Certs,
								String s) throws CertificateException {
						}
	
						public void checkServerTrusted(X509Certificate[] x509Certs,
								String s) throws CertificateException {
						}
	
						public X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[0];
						}
					};
					SSLContext sslContext = SSLContext.getInstance("TLS");
					sslContext.init(null, new TrustManager[] { tm }, null);
					socketFactory = sslContext.getSocketFactory();
				}
			
				con = u.openConnection();
	
				if (Boolean.parseBoolean(p.getProperty(
						"ssl.server.certificate.validation", "true")) != true) {
					((HttpsURLConnection)con).setSSLSocketFactory(socketFactory);
				}
	
				if (Boolean.parseBoolean(p.getProperty("ssl.hostname.verification",
						"true")) != true) {
	
					hv = new HostnameVerifier() {
						public boolean verify(String urlHostName, SSLSession session) {
							return true;
						}
	
					};
					((HttpsURLConnection)con).setHostnameVerifier(hv);
				}
			} else {
				con = u.openConnection();				
			}

			con.setRequestProperty("ping.uname",
					p.getProperty(type + ".adapter.username"));
			con.setRequestProperty("ping.pwd",
					p.getProperty(type + ".adapter.password"));
			con.setRequestProperty("ping.instanceId",
					p.getProperty(type + ".adapter.id"));

			if (jsonRespObj != null) {
				con.setDoOutput(true);
				OutputStreamWriter outputStreamWriter = new OutputStreamWriter(
						con.getOutputStream(), "UTF-8");
				jsonRespObj.writeJSONString(outputStreamWriter);
				outputStreamWriter.flush();
				outputStreamWriter.close();
			}
			InputStream ins = con.getInputStream();
			InputStreamReader isr = new InputStreamReader(ins);
			JSONParser parser = new JSONParser();
			return (JSONObject) parser.parse(isr);

		} catch (Exception e) {
			throw new IOException(e);
		}

	}

	/**
	 * Get the base URL
	 */
	public String getBaseURL(Properties p, HttpServletRequest request, String propertyKey) {
		if (propertyKey != null) {
			if ((p.getProperty(propertyKey) != null)
					&& (!p.getProperty(propertyKey).equals("")))
				return p.getProperty(propertyKey);			
		}		
		if ((p.getProperty("pf.base.url") != null)
				&& (!p.getProperty("pf.base.url").equals("")))
			return p.getProperty("pf.base.url");
		StringBuffer url = request.getRequestURL();
		String ctx = request.getContextPath();
		return url.substring(0, url.length() - ctx.length() - 1);
	}
	
	/**
	 * Pickup attributes from PingFederate using the Agentless protocol.
	 */
	public JSONObject doPickup(Properties p, String role,
			HttpServletRequest request, HttpServletResponse response,
			SessionStateSupport sessionStateSupport) throws IOException {
		String pickupUrl = getBaseURL(p, request, "pf.backchannel.url") + "/ext/ref/pickup?REF="
				+ URLEncoder.encode(request.getParameter("REF"), "UTF-8");
		JSONObject jsonObject = doREST(pickupUrl, p, role, null);
		sessionStateSupport.setAttribute("state", new ProxySSOSessionState(
				jsonObject), request, response, false);
		return jsonObject;
	}

	/**
	 * Drop-off attributes to PingFederate using the Agentless protocol.
	 */
	public String doDropoff(Properties p, String role,
			HttpServletRequest request, HttpServletResponse response,
			SessionStateSupport sessionStateSupport) throws IOException {
		String dropoffUrl = getBaseURL(p, request, "pf.backchannel.url") + "/ext/ref/dropoff";
		ProxySSOSessionState state = (ProxySSOSessionState) sessionStateSupport
				.getAttribute("state", request, response);
		JSONObject jsonObject = doREST(dropoffUrl, p, role,
				state.getJSONObject());
		return (String) jsonObject.get("REF");
	}

	/**
	 * send off the browser to the resumePath to PingFederate
	 */
	public void doResume(Properties p, String resumePath,
			HttpServletRequest request, HttpServletResponse response, String ref)
			throws IOException {
		String strReturnUrl = getBaseURL(p, request, null) + resumePath + "?REF="
				+ URLEncoder.encode(ref, "UTF-8");
		response.sendRedirect(strReturnUrl);
	}

	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		String cmdValue = request.getParameter("cmd");
		String propsFileName = (request.getParameter("props") == null) ? "proxy"
				: request.getParameter("props");

		// for storing stuff in the session information that is shared in a
		// cluster
		SessionStateSupport sessionStateSupport = new SessionStateSupport();

		InputStream stream = request.getServletContext().getResourceAsStream(
				"/" + propsFileName + ".properties");
		Properties p = new Properties();
		p.load(stream);
		long sessionExpiryTimeout = Long.valueOf(p.getProperty(
				"session.timeout", "0"));
		long sessionIdleTimeout = Long.valueOf(p.getProperty(
				"session.idle.timeout", "0"));
		boolean sessionAuthnInstUpdate = Boolean.parseBoolean(p.getProperty(
				"session.authninst.update", "false"));

		if (cmdValue == null) {

			if (request.getParameter("REF") == null) {
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().write("<html><body>");
				response.getWriter().write("<title>Hans' Proxy</title>");
				response.getWriter().write(
						"<h3>Hans' Proxy - version " + proxyVersion + "</h3>");
				response.getWriter().write(
						"<p><i><small>(loaded " + p.size()
								+ " properties)</small></i></p>");
				response.getWriter().write(
						"<p>Nothing to see here, please move along...</p>");
				response.getWriter()
						.write("<p>Documentation can be found <a href=\"https://github.com/zandbelt/pingfederate-proxy-jsp/blob/master/proxy-3.0.pdf?raw=true\">here</a>.</p>");

				response.getWriter().write("<p><pre><table>");
				Enumeration<String> headerNames = request.getHeaderNames();
				while (headerNames.hasMoreElements()) {
					response.getWriter().write("<tr><td>");
					String headerName = headerNames.nextElement();
					response.getWriter().write(headerName);
					response.getWriter().write("</td><td>");
					Enumeration<String> headers = request
							.getHeaders(headerName);
					while (headers.hasMoreElements()) {
						String headerValue = headers.nextElement();
						response.getWriter().write(headerValue);
						response.getWriter().write("</td><td>");
					}
					response.getWriter().write("</td></tr>");
				}
				response.getWriter().write("</table></pre></p>");

				response.getWriter().write("</body><html>");
				response.getWriter().flush();
				return;
			}

			// start IDP-initiated-SSO
			doPickup(p, "sp", request, response, sessionStateSupport);

			sessionStateSupport.setAttribute("needs-slo", "", request,
					response, false);
			
			String strReturnUrl = getBaseURL(p, request, null);
			String idpAdapterId = (request.getParameter("IdpAdapterId") != null) ? request
					.getParameter("IdpAdapterId") : p
					.getProperty("idp.adapter.id");
			strReturnUrl += "/idp/startSSO.ping?IdpAdapterId="
					+ URLEncoder.encode(idpAdapterId, "UTF-8");
			if (request.getParameter("PartnerSpId") != null)
				strReturnUrl += "&PartnerSpId="
						+ URLEncoder.encode(
								request.getParameter("PartnerSpId"), "UTF-8");
			if (request.getParameter("TargetResource") != null)
				strReturnUrl += "&TargetResource="
						+ URLEncoder
								.encode(request.getParameter("TargetResource"),
										"UTF-8");
			strReturnUrl += "&REF="
					+ URLEncoder.encode(
							doDropoff(p, "idp", request, response,
									sessionStateSupport), "UTF-8");

			response.sendRedirect(strReturnUrl);

		} else if (cmdValue.equals("check-sso")) {

			ProxySSOSessionState state = (ProxySSOSessionState) sessionStateSupport
					.getAttribute("state", request, response);

			String result = ((state != null) && (state.isValid(
					sessionExpiryTimeout, sessionIdleTimeout))) ? "yes" : "no";

			String strReturnUrl = request.getParameter("return");
			strReturnUrl += (strReturnUrl.indexOf("?") > -1) ? "&" : "?";
			strReturnUrl += "check-sso=" + result;

			response.sendRedirect(strReturnUrl);
			
		} else if (cmdValue.equals("idp-sso")) {

			ProxySSOSessionState state = (ProxySSOSessionState) sessionStateSupport
					.getAttribute("state", request, response);

			if ((state != null)
					&& (state.isValid(sessionExpiryTimeout, sessionIdleTimeout))) {

				if (sessionAuthnInstUpdate) {
					SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ");
					state.jsonObject.put("authnInst", fmt.format(new Date()));
				}
				
				// continue IDP initiated SSO
				doResume(
						p,
						request.getParameter("resumePath"),
						request,
						response,
						doDropoff(p, "idp", request, response,
								sessionStateSupport));

			} else {

				if (state != null) {
					sessionStateSupport.removeAttribute("state", request,
							response);
				}

				boolean allowInteraction = request
						.getParameter("allowInteraction") != null ? Boolean
						.parseBoolean(request.getParameter("allowInteraction"))
						: true;

				if ((sessionExpiryTimeout > 0) && (allowInteraction == false)) {
					// create empty JSON object so login is required and PF will
					// return an error to the caller
					state = new ProxySSOSessionState(new JSONObject());
					sessionStateSupport.setAttribute("state", state, request,
							response, false);
					doResume(
							p,
							request.getParameter("resumePath"),
							request,
							response,
							doDropoff(p, "idp", request, response,
									sessionStateSupport));
					sessionStateSupport.removeAttribute("state", request,
							response);
					return;
				}

				// this is an SP request to the IDP adapter that we forward to
				// the IDP Discovery page for the SP adapter

				// assemble the URL to CDC endpoint and send the browser off
				String startSSOUrl = getBaseURL(p, request, "pf.discovery.url");

				startSSOUrl += (request.getParameter("startsso") != null) ? request
						.getParameter("startsso") : p.getProperty(
						"pf.start.sso.path", "/sp/cdcstartSSO.ping");
				startSSOUrl += (startSSOUrl.indexOf("?") > -1) ? "&" : "?";
				startSSOUrl += "SpSessionAuthnAdapterId="
						+ URLEncoder.encode(p.getProperty("sp.adapter.id"),
								"UTF-8");
				// kick off url:
				// https://proxy:9031/pf/adapter2adapter.ping?SpSessionAuthnAdapterId=spadapter&IdpAdapterId=proxyidpadapter2
				// proxyidpadapter2 adapter auth service url:
				// https://proxy:9031/proxy/?cmd=idp-sso&startsso=%2Fpf%2Fadapter2adapter.ping&IdpAdapterId=facebook
				if (request.getParameter("IdpAdapterId") != null) {
					startSSOUrl += "&IdpAdapterId="
							+ URLEncoder.encode(
									request.getParameter("IdpAdapterId"),
									"UTF-8");
				}
				if (request.getParameter("PartnerIdpId") != null) {
					startSSOUrl += "&PartnerIdpId="
							+ URLEncoder.encode(
									request.getParameter("PartnerIdpId"),
									"UTF-8");
				}
				String targetResource = getBaseURL(p, request, null)
						+ p.getProperty("proxy.path");
				targetResource += "?cmd=idp-sso-resume&resumePath="
						+ URLEncoder.encode(request.getParameter("resumePath"),
								"UTF-8");
				if ((request.getParameter("props") != null)) {
					targetResource += "&props="
							+ URLEncoder.encode(request.getParameter("props"),
									"UTF-8");
				}
				startSSOUrl += "&TargetResource="
						+ URLEncoder.encode(targetResource, "UTF-8");
				response.sendRedirect(startSSOUrl);

			}

		} else if (cmdValue.equals("idp-sso-resume")) {
			// this is a response from the IDP to the SP adapter that we forward
			// to the SP through the IDP adapter
			
			sessionStateSupport.setAttribute("needs-slo", "", request,
					response, false);
			
			doPickup(p, "sp", request, response, sessionStateSupport);
			doResume(p, request.getParameter("resumePath"), request, response,
					doDropoff(p, "idp", request, response, sessionStateSupport));

		} else if (cmdValue.equals("sp-slo")) {

			// this is a logout request from the IDP through the SP adapter
			JSONObject jsonObj = doPickup(p, "sp", request, response,
					sessionStateSupport);

			if (sessionStateSupport.getAttribute("needs-slo", request, response) == null ) {

				// SLO was already initiated by peer leg so just resume
				// send off the browser to the resumePath, ie. to the IDP
				doResume(p, (String) jsonObj.get("resumePath"), request,
						response, request.getParameter("REF"));

			} else {

				sessionStateSupport.removeAttribute("needs-slo", request, response);

				// assemble the URL to SLO endpoint and send the browser off to
				// the SP through the IDP adapter
				String startSLOUrl = getBaseURL(p, request, null)
						+ "/idp/startSLO.ping";
				String targetResource = getBaseURL(p, request, null)
						+ p.getProperty("proxy.path");
				targetResource += "?cmd=slo-resume&resumePath="
						+ URLEncoder.encode((String) jsonObj.get("resumePath"),
								"UTF-8");
				targetResource += "&REF="
						+ URLEncoder.encode(request.getParameter("REF"),
								"UTF-8");
				if ((request.getParameter("props") != null)) {
					targetResource += "&props="
							+ URLEncoder.encode(request.getParameter("props"),
									"UTF-8");
				}
				startSLOUrl += "?TargetResource="
						+ URLEncoder.encode(targetResource, "UTF-8");
				response.sendRedirect(startSLOUrl);

			}

		} else if (cmdValue.equals("idp-slo")) {

			// this is a logout request from the SP through the IDP adapter
			JSONObject jsonObj = doPickup(p, "idp", request, response,
					sessionStateSupport);

			if (sessionStateSupport.getAttribute("needs-slo", request, response) == null ) {
				
				// SLO was already initiated by peer leg so just resume
				// send off the browser to the resumePath, ie. to the SP
				doResume(p, (String) jsonObj.get("resumePath"), request,
						response, request.getParameter("REF"));

			} else {

				sessionStateSupport.removeAttribute("needs-slo", request, response);
				
				// assemble the URL to SLO endpoint and send the browser off to
				// the IDP through the SP adapter
				String startSLOUrl = getBaseURL(p, request, null);
				startSLOUrl += "/sp/startSLO.ping?SpSessionAuthnAdapterId="
						+ URLEncoder.encode(p.getProperty("sp.adapter.id"),
								"UTF-8");
				String targetResource = getBaseURL(p, request, null)
						+ p.getProperty("proxy.path");
				targetResource += "?cmd=slo-resume&resumePath="
						+ URLEncoder.encode((String) jsonObj.get("resumePath"),
								"UTF-8");
				targetResource += "&REF="
						+ URLEncoder.encode(request.getParameter("REF"),
								"UTF-8");
				if ((request.getParameter("props") != null)) {
					targetResource += "&props="
							+ URLEncoder.encode(request.getParameter("props"),
									"UTF-8");
				}
				startSLOUrl += "&TargetResource="
						+ URLEncoder.encode(targetResource, "UTF-8");
				response.sendRedirect(startSLOUrl);

			}

		} else if (cmdValue.equals("slo-resume")) {

			// kill the session and send off the browser to the resumePath, ie.
			// to the IDP/SP
			sessionStateSupport.removeAttribute("state", request, response);
			doResume(p, request.getParameter("resumePath"), request, response,
					request.getParameter("REF"));

		} else {

			response.getWriter().print("Invalid request: \"" + cmdValue + "\"");

		}

	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}
}
