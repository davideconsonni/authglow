# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 4 |
| Low | 3 |
| Informational | 4 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP errors logged - see the zap.log file for details | 31    |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 4    |
| Info | Informational | http://host.docker.internal:5173 | Percentage of authentication failures | 100 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 1xx | 1 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 2xx | 71 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 3xx | 25 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 4xx | 1 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with content type application/json | 8 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with content type text/html | 1 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with method GET | 98 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with method POST | 1 % |
| Info | Informational | http://host.docker.internal:5173 | Count of total endpoints | 86    |
| Info | Informational | http://host.docker.internal:5173 | Percentage of slow responses | 2 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of responses with status code 2xx | 8 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of responses with status code 4xx | 90 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with content type application/json | 100 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method DELETE | 9 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method GET | 41 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method PATCH | 3 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method POST | 42 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method PUT | 3 % |
| Info | Informational | http://host.docker.internal:8001 | Count of total endpoints | 197    |
| Info | Informational | http://host.docker.internal:8001 | Percentage of slow responses | 1 % |
| Info | Informational | https://fonts.googleapis.com | Percentage of responses with status code 2xx | 100 % |
| Info | Informational | https://fonts.googleapis.com | Percentage of slow responses | 100 % |
| Info | Informational | https://fonts.gstatic.com | Percentage of responses with status code 2xx | 100 % |
| Info | Informational | https://fonts.gstatic.com | Percentage of slow responses | 8 % |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Content Security Policy (CSP) Header Not Set | Medium | 2 |
| Missing Anti-clickjacking Header | Medium | 2 |
| Sub Resource Integrity Attribute Missing | Medium | 2 |
| Weak Authentication Method | Medium | 2 |
| Application Error Disclosure | Low | 1 |
| Information Disclosure - Debug Error Messages | Low | 1 |
| X-Content-Type-Options Header Missing | Low | 2 |
| Authentication Request Identified | Informational | 6 |
| Information Disclosure - Sensitive Information in URL | Informational | 6 |
| Modern Web Application | Informational | 2 |
| Session Management Response Identified | Informational | 3 |




## Alert Detail



### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://host.docker.internal:5173
  * Node Name: `http://host.docker.internal:5173`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 2

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: http://host.docker.internal:5173
  * Node Name: `http://host.docker.internal:5173`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 2

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Sub Resource Integrity Attribute Missing ](https://www.zaproxy.org/docs/alerts/90003/)



##### Medium (High)

### Description

The integrity attribute is missing on a script or link tag served by an external server. The integrity tag prevents an attacker who have gained access to this server from injecting a malicious content.

* URL: http://host.docker.internal:5173
  * Node Name: `http://host.docker.internal:5173`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />`
  * Other Info: ``
* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />`
  * Other Info: ``


Instances: 2

### Solution

Provide a valid integrity attribute to the tag.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity ](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)


#### CWE Id: [ 345 ](https://cwe.mitre.org/data/definitions/345.html)


#### WASC Id: 15

#### Source ID: 3

### [ Weak Authentication Method ](https://www.zaproxy.org/docs/alerts/10105/)



##### Medium (Medium)

### Description

HTTP basic or digest authentication has been used over an unsecured connection. The credentials can be read and then reused by someone with access to the network.

* URL: http://host.docker.internal:8001/oauth2/register/client_id
  * Node Name: `http://host.docker.internal:8001/oauth2/register/client_id`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `www-authenticate: Basic realm="OAuth2", Bearer realm="OAuth2", client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
  * Other Info: ``
* URL: http://host.docker.internal:8001/oauth2/register/client_id
  * Node Name: `http://host.docker.internal:8001/oauth2/register/client_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `www-authenticate: Basic realm="OAuth2", Bearer realm="OAuth2", client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
  * Other Info: ``


Instances: 2

### Solution

Protect the connection using HTTPS or use a stronger authentication mechanism.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)


#### CWE Id: [ 326 ](https://cwe.mitre.org/data/definitions/326.html)


#### WASC Id: 4

#### Source ID: 3

### [ Application Error Disclosure ](https://www.zaproxy.org/docs/alerts/90022/)



##### Low (Medium)

### Description

This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.

* URL: http://host.docker.internal:8001/api/passkey/auth/complete
  * Node Name: `http://host.docker.internal:8001/api/passkey/auth/complete ()({credential_id,client_data_json,authenticator_data,signature,user_handle})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``


Instances: 1

### Solution

Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.

### Reference



#### CWE Id: [ 550 ](https://cwe.mitre.org/data/definitions/550.html)


#### WASC Id: 13

#### Source ID: 3

### [ Information Disclosure - Debug Error Messages ](https://www.zaproxy.org/docs/alerts/10023/)



##### Low (Medium)

### Description

The response appeared to contain common error messages returned by platforms such as ASP.NET, and Web-servers such as IIS and Apache. You can configure the list of common debug messages.

* URL: http://host.docker.internal:8001/api/passkey/auth/complete
  * Node Name: `http://host.docker.internal:8001/api/passkey/auth/complete ()({credential_id,client_data_json,authenticator_data,signature,user_handle})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Internal server error`
  * Other Info: ``


Instances: 1

### Solution

Disable debugging messages before pushing to production.

### Reference



#### CWE Id: [ 1295 ](https://cwe.mitre.org/data/definitions/1295.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://host.docker.internal:5173
  * Node Name: `http://host.docker.internal:5173`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`


Instances: 2

### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (Low)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://host.docker.internal:8001/api/admin/users/create
  * Node Name: `http://host.docker.internal:8001/api/admin/users/create ()({email,password,first_name,last_name,phone,avatar_url,scopes:[],roles:[],email_verified})`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=password`
* URL: http://host.docker.internal:8001/api/auth/expired-password/change
  * Node Name: `http://host.docker.internal:8001/api/auth/expired-password/change ()({email,current_password,new_password})`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `current_password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=current_password`
* URL: http://host.docker.internal:8001/api/oauth2/authorize
  * Node Name: `http://host.docker.internal:8001/api/oauth2/authorize ()(claims,client_id,code_challenge,code_challenge_method,email,id_token_hint,max_age,nonce,password,prompt,redirect_uri,response_type,scope,state)`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=password`
* URL: http://host.docker.internal:8001/api/profile/me/change-email
  * Node Name: `http://host.docker.internal:8001/api/profile/me/change-email ()({new_email,password})`
  * Method: `POST`
  * Parameter: `new_email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=new_email
userValue=John Doe
passwordParam=password`
* URL: http://host.docker.internal:8001/api/setup/create-admin
  * Node Name: `http://host.docker.internal:8001/api/setup/create-admin ()({email,password,first_name,last_name})`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=password`
* URL: http://host.docker.internal:8001/api/users
  * Node Name: `http://host.docker.internal:8001/api/users ()({email,password,first_name,last_name})`
  * Method: `POST`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=email
userValue=zaproxy@example.com
passwordParam=password`


Instances: 6

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Information Disclosure - Sensitive Information in URL ](https://www.zaproxy.org/docs/alerts/10024/)



##### Informational (Medium)

### Description

The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.

* URL: http://host.docker.internal:5173/%3Ftoken=KTOEDdElIoVF
  * Node Name: `http://host.docker.internal:5173/ (token)`
  * Method: `GET`
  * Parameter: `token`
  * Attack: ``
  * Evidence: `token`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: token
token`
* URL: http://host.docker.internal:8001/api/admin/oauth-consents%3Femail=zaproxy@example.com&limit=50&offset=0
  * Node Name: `http://host.docker.internal:8001/api/admin/oauth-consents (email,limit,offset)`
  * Method: `GET`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `zaproxy@example.com`
  * Other Info: `The URL contains email address(es).`
* URL: http://host.docker.internal:8001/api/admin/sessions%3Femail=zaproxy@example.com&type=all&limit=50&offset=0
  * Node Name: `http://host.docker.internal:8001/api/admin/sessions (email,limit,offset,type)`
  * Method: `GET`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `zaproxy@example.com`
  * Other Info: `The URL contains email address(es).`
* URL: http://host.docker.internal:8001/api/demo/inbox%3Femail=zaproxy@example.com
  * Node Name: `http://host.docker.internal:8001/api/demo/inbox (email)`
  * Method: `GET`
  * Parameter: `email`
  * Attack: ``
  * Evidence: `zaproxy@example.com`
  * Other Info: `The URL contains email address(es).`
* URL: http://host.docker.internal:8001/api/oauth2/consent/check%3Fsession_token=session_token
  * Node Name: `http://host.docker.internal:8001/api/oauth2/consent/check (session_token)`
  * Method: `GET`
  * Parameter: `session_token`
  * Attack: ``
  * Evidence: `session_token`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: token
session_token`
* URL: http://host.docker.internal:8001/oauth2/logout%3Fid_token_hint=&post_logout_redirect_uri=&state=Oklahoma
  * Node Name: `http://host.docker.internal:8001/oauth2/logout (id_token_hint,post_logout_redirect_uri,state)`
  * Method: `GET`
  * Parameter: `id_token_hint`
  * Attack: ``
  * Evidence: `id_token_hint`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: token
id_token_hint`


Instances: 6

### Solution

Do not pass sensitive information in URIs.

### Reference



#### CWE Id: [ 598 ](https://cwe.mitre.org/data/definitions/598.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

* URL: http://host.docker.internal:5173
  * Node Name: `http://host.docker.internal:5173`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script type="module">import { injectIntoGlobalHook } from "/@react-refresh";
injectIntoGlobalHook(window);
window.$RefreshReg$ = () => {};
window.$RefreshSig$ = () => (type) => type;</script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`


Instances: 2

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://host.docker.internal:5173/api/oauth2/csrf-token
  * Node Name: `http://host.docker.internal:5173/api/oauth2/csrf-token`
  * Method: `GET`
  * Parameter: `csrf_session_id`
  * Attack: ``
  * Evidence: `csrf_session_id`
  * Other Info: `cookie:csrf_session_id`
* URL: http://host.docker.internal:8001/api/oauth2/csrf-token
  * Node Name: `http://host.docker.internal:8001/api/oauth2/csrf-token`
  * Method: `GET`
  * Parameter: `csrf_session_id`
  * Attack: ``
  * Evidence: `csrf_session_id`
  * Other Info: `cookie:csrf_session_id`
* URL: http://host.docker.internal:5173/api/oauth2/csrf-token
  * Node Name: `http://host.docker.internal:5173/api/oauth2/csrf-token`
  * Method: `GET`
  * Parameter: `csrf_session_id`
  * Attack: ``
  * Evidence: `csrf_session_id`
  * Other Info: `cookie:csrf_session_id`


Instances: 3

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3


