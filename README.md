Hans' PingFederate Proxy
========================

This proxy is a Java Servlet that allows bridging between connections in PingFederate.

*Note: this component is now superseded by the native federation hub capabilities 
that were introduced in PingFederate 7.3: http://documentation.pingidentity.com/display/PF73/Federation+Hub
and rolled-up and generalized in PingFederate 8.1 though the concept of Advanced Authentication Policies: https://documentation.pingidentity.com/pingfederate/pf81/index.shtml#adminGuide/concept/connectionMappingContracts.html*

Installation
------------

1. download PingFederate 7.x/8.x and deploy it together with a license file

2. install the Agentless Integration Kit 1.2
 
3. copy the proxy.war directory and the proxy.jar file in server/default/deploy (using cp -r)

4. configure one IDP and one SP Reference ID adapter with the settings below

5. enable target resource validation in the SP configuration application integration
   settings and lock down the TargetResource to the PingFederate proxy hostname

6. connect the defined Reference ID IDP and SP adapters to each of the SP and IDP
   connections respectively that you want to bridge to/from

7. review proxy.war/proxy.properties and edit as needed; typically only the hostname 
   since version 3.0 SSO sessions on the proxy are supported, cached for the duration
   of the `session.timeout setting`

The proxy IDP adapter can be instantiated multiple times, inheriting from a single parent,
to represent individual IDPs; the authentication service URL would then be extended with a
PartnerIdpId. IDP selection can then be done by connecting a specific proxy IDP adapter
instance to a connection, possibly using adapter selection for IDP groups, or in the
adapter2adapter case by passing in the IdpAdapterId after creating corresponding mappings.

For the Agentless Adapter 1.2 use the POST Transport Mode for best security.

**SP Proxy Adapter Settings**

    Instance Name	Proxy SP Adapter
    Instance Id	ProxySpAdapter
    User Name	ref
    Password ref1234
    Logout Service Endpoint	https://<hostname>:9031/proxy/?cmd=sp-slo
    Transport Mode	Form Post
    Require SSL/TLS	true
    Outgoing Attribute Format	JSON
    Incoming Attribute Format	JSON
    Logout Mode	Front Channel
    Skip Host Name Validation	false

For Agentless Adapter >= 1.2 leave the following entry empty:

    Authentication Endpoint

<and an attribute contract for all attributes you want to pass over the bridge>

**IDP Proxy Adapter Settings**

    Instance Name	Proxy IDP Adapter
    Instance Id	ProxyIDPAdapter
    Authentication Endpoint	https://<hostname>:9031/proxy/?cmd=idp-sso
    User Name	ref
    Password ref1234
    Logout Service Endpoint	https://<hostname>:9031/proxy/?cmd=idp-slo
    Transport Mode	Form Post
    Require SSL/TLS	true
    Outgoing Attribute Format	JSON
    Incoming Attribute Format	JSON
    Logout Mode	Front Channel
    Skip Host Name Validation	false

<and an attribute contract for all attributes you want to pass over the bridge>

If you want to use different SP/IDP adapter pairs pointing to the same proxy.war instance but
leveraging different property files (e.g. for different IDP/SP pairings), you can add a
`props=<filename-without.suffix` parameter to the (cmd=) URLs in the configurations above and 
put the properties file(s) in the proxy.war directory alongside of the default `proxy.properties`.
