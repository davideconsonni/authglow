# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 2 |
| Medium | 5 |
| Low | 4 |
| Informational | 6 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP errors logged - see the zap.log file for details | 1    |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 545    |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 1xx | 1 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 2xx | 47 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 3xx | 47 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of responses with status code 4xx | 4 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with content type application/json | 7 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with content type text/javascript | 82 % |
| Info | Informational | http://host.docker.internal:5173 | Percentage of endpoints with method GET | 99 % |
| Info | Informational | http://host.docker.internal:5173 | Count of total endpoints | 114    |
| Info | Informational | http://host.docker.internal:5173 | Percentage of slow responses | 1 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of responses with status code 2xx | 10 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of responses with status code 4xx | 88 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with content type application/json | 100 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method DELETE | 5 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method GET | 64 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method PATCH | 2 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method POST | 25 % |
| Info | Informational | http://host.docker.internal:8001 | Percentage of endpoints with method PUT | 2 % |
| Info | Informational | http://host.docker.internal:8001 | Count of total endpoints | 330    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Path Traversal | High | 4 |
| SQL Injection | High | 2 |
| Content Security Policy (CSP) Header Not Set | Medium | 1 |
| Format String Error | Medium | 1 |
| Missing Anti-clickjacking Header | Medium | 1 |
| Sub Resource Integrity Attribute Missing | Medium | 1 |
| Weak Authentication Method | Medium | 2 |
| Application Error Disclosure | Low | 1 |
| Information Disclosure - Debug Error Messages | Low | 1 |
| Timestamp Disclosure - Unix | Low | 1 |
| X-Content-Type-Options Header Missing | Low | Systemic |
| Authentication Request Identified | Informational | 6 |
| Information Disclosure - Sensitive Information in URL | Informational | 6 |
| Information Disclosure - Suspicious Comments | Informational | 41 |
| Modern Web Application | Informational | 1 |
| Session Management Response Identified | Informational | 2 |
| User Agent Fuzzer | Informational | Systemic |




## Alert Detail



### [ Path Traversal ](https://www.zaproxy.org/docs/alerts/6/)



##### High (Low)

### Description

The Path Traversal attack technique allows an attacker access to files, directories, and commands that potentially reside outside the web document root directory. An attacker may manipulate a URL in such a way that the web site will execute or reveal the contents of arbitrary files anywhere on the web server. Any device that exposes an HTTP-based interface is potentially vulnerable to Path Traversal.

Most web sites restrict user access to a specific portion of the file-system, typically called the "web document root" or "CGI root" directory. These directories contain the files intended for user access and the executable necessary to drive web application functionality. To access files or execute commands anywhere on the file-system, Path Traversal attacks will utilize the ability of special-characters sequences.

The most basic Path Traversal attack uses the "../" special-character sequence to alter the resource location requested in the URL. Although most popular web servers will prevent this technique from escaping the web document root, alternate encodings of the "../" sequence may help bypass the security filters. These method variations include valid and invalid Unicode-encoding ("..%u2216" or "..%c0%af") of the forward slash character, backslash characters ("..\") on Windows-based servers, URL encoded characters "%2e%2e%2f"), and double URL encoding ("..%255c") of the backslash character.

Even if the web server properly restricts Path Traversal attempts in the URL path, a web application itself may still be vulnerable due to improper handling of user-supplied input. This is a common problem of web applications that use template mechanisms or load static text from files. In variations of the attack, the original URL parameter value is substituted with the file name of one of the web application's dynamic scripts. Consequently, the results can reveal source code because the file is interpreted as text instead of an executable script. These techniques often employ additional special characters such as the dot (".") to reveal the listing of the current working directory, or "%00" NULL characters in order to bypass rudimentary file extension checks.

* URL: http://host.docker.internal:5173/node_modules/.vite/deps/clsx.js%3Fv=%252Fclsx.js
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/clsx.js (v)`
  * Method: `GET`
  * Parameter: `v`
  * Attack: `/clsx.js`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/rolldown-runtime-DC62tzP2.js%3Fv=%252Frolldown-runtime-DC62tzP2.js
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/rolldown-runtime-DC62tzP2.js (v)`
  * Method: `GET`
  * Parameter: `v`
  * Attack: `/rolldown-runtime-DC62tzP2.js`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js%3Fv=%252Ftailwind-merge.js
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js (v)`
  * Method: `GET`
  * Parameter: `v`
  * Attack: `/tailwind-merge.js`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/zustand.js%3Fv=%252Fzustand.js
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/zustand.js (v)`
  * Method: `GET`
  * Parameter: `v`
  * Attack: `/zustand.js`
  * Evidence: ``
  * Other Info: ``


Instances: 4

### Solution

Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use an allow list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a deny list). However, deny lists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.

When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if you are expecting colors such as "red" or "blue."

For filenames, use stringent allow lists that limit the character set to be used. If feasible, only allow a single "." character in the filename to avoid weaknesses, and exclude directory separators such as "/". Use an allow list of allowable file extensions.

Warning: if you attempt to cleanse your data, then do so that the end result is not in the form that can be dangerous. A sanitizing mechanism can remove characters such as '.' and ';' which may be required for some exploits. An attacker can try to fool the sanitizing mechanism into "cleaning" data into a dangerous form. Suppose the attacker injects a '.' inside a filename (e.g. "sensi.tiveFile") and the sanitizing mechanism removes the character resulting in the valid filename, "sensitiveFile". If the input data are now assumed to be safe, then the file may be compromised. 

Inputs should be decoded and canonicalized to the application's current internal representation before being validated. Make sure that your application does not decode the same input twice. Such errors could be used to bypass allow list schemes by introducing dangerous inputs after they have been checked.

Use a built-in path canonicalization function (such as realpath() in C) that produces the canonical version of the pathname, which effectively removes ".." sequences and symbolic links.

Run your code using the lowest privileges that are required to accomplish the necessary tasks. If possible, create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations.

When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.

Run your code in a "jail" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a particular directory or which commands can be executed by your software.

OS-level examples include the Unix chroot jail, AppArmor, and SELinux. In general, managed code may provide some protection. For example, java.io.FilePermission in the Java SecurityManager allows you to specify restrictions on file operations.

This may not be a feasible solution, and it only limits the impact to the operating system; the rest of your application may still be subject to compromise.


### Reference


* [ https://owasp.org/www-community/attacks/Path_Traversal ](https://owasp.org/www-community/attacks/Path_Traversal)
* [ https://cwe.mitre.org/data/definitions/22.html ](https://cwe.mitre.org/data/definitions/22.html)


#### CWE Id: [ 22 ](https://cwe.mitre.org/data/definitions/22.html)


#### WASC Id: 33

#### Source ID: 1

### [ SQL Injection ](https://www.zaproxy.org/docs/alerts/40018/)



##### High (Medium)

### Description

SQL injection may be possible.

* URL: http://host.docker.internal:8001/api/federation/login/%2522%3Fredirect_uri=/auth/callback&acr_values=&client_id=&oauth_redirect_uri=&scope=&app_state=&code_challenge=&code_challenge_method=&response_type=&oidc_nonce=
  * Node Name: `http://host.docker.internal:8001/api/federation/login/" (acr_values,app_state,client_id,code_challenge,code_challenge_method,oauth_redirect_uri,oidc_nonce,redirect_uri,response_type,scope)`
  * Method: `GET`
  * Parameter: `«provider_id»`
  * Attack: `"`
  * Evidence: `HTTP/1.1 500 Internal Server Error`
  * Other Info: ``
* URL: http://host.docker.internal:8001/api/federation/callback%3Fcode=code+AND+1%253D1+--+&state=Oklahoma&provider_id=
  * Node Name: `http://host.docker.internal:8001/api/federation/callback (code,provider_id,state)`
  * Method: `GET`
  * Parameter: `code`
  * Attack: `code AND 1=1 -- `
  * Evidence: ``
  * Other Info: `The page results were successfully manipulated using the boolean conditions [code AND 1=1 -- ] and [code AND 1=2 -- ]
The parameter value being modified was stripped from the HTML output for the purposes of the comparison.
Data was returned for the original parameter.
The vulnerability was detected by successfully restricting the data originally returned, by manipulating the parameter.`


Instances: 2

### Solution

Do not trust client side input, even if there is client side validation in place.
In general, type check all data on the server side.
If the application uses JDBC, use PreparedStatement or CallableStatement, with parameters passed by '?'
If the application uses ASP, use ADO Command Objects with strong type checking and parameterized queries.
If database Stored Procedures can be used, use them.
Do *not* concatenate strings into queries in the stored procedure, or use 'exec', 'exec immediate', or equivalent functionality!
Do not create dynamic SQL queries using simple string concatenation.
Escape all data received from the client.
Apply an 'allow list' of allowed characters, or a 'deny list' of disallowed characters in user input.
Apply the principle of least privilege by using the least privileged database user possible.
In particular, avoid using the 'sa' or 'db-owner' database users. This does not eliminate SQL injection, but minimizes its impact.
Grant the minimum database access that is necessary for the application.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)


#### CWE Id: [ 89 ](https://cwe.mitre.org/data/definitions/89.html)


#### WASC Id: 19

#### Source ID: 1

### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 1

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

### [ Format String Error ](https://www.zaproxy.org/docs/alerts/30002/)



##### Medium (Medium)

### Description

A Format String error occurs when the submitted data of an input string is evaluated as a command by the application.

* URL: http://host.docker.internal:8001/api/federation/login/ZAP%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%2525n%2525s%250A%3Fredirect_uri=/auth/callback&acr_values=&client_id=&oauth_redirect_uri=&scope=&app_state=&code_challenge=&code_challenge_method=&response_type=&oidc_nonce=
  * Node Name: `http://host.docker.internal:8001/api/federation/login/ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
 (acr_values,app_state,client_id,code_challenge,code_challenge_method,oauth_redirect_uri,oidc_nonce,redirect_uri,response_type,scope)`
  * Method: `GET`
  * Parameter: `«provider_id»`
  * Attack: `ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a /%s.`


Instances: 1

### Solution

Rewrite the background program using proper deletion of bad character strings. This will require a recompile of the background executable.

### Reference


* [ https://owasp.org/www-community/attacks/Format_string_attack ](https://owasp.org/www-community/attacks/Format_string_attack)


#### CWE Id: [ 134 ](https://cwe.mitre.org/data/definitions/134.html)


#### WASC Id: 6

#### Source ID: 1

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 1

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

* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />`
  * Other Info: ``


Instances: 1

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

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: http://host.docker.internal:5173/node_modules/.vite/deps/react-dom_client.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/react-dom_client.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2080374784`
  * Other Info: `2080374784, which evaluates to: 2035-12-04 09:53:04.`


Instances: 1

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://host.docker.internal:5173/
  * Node Name: `http://host.docker.internal:5173/`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/react_jsx-dev-runtime.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/react_jsx-dev-runtime.js (v)`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:5173/node_modules/vite/dist/client/env.mjs
  * Node Name: `http://host.docker.internal:5173/node_modules/vite/dist/client/env.mjs`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:5173/src/main.tsx
  * Node Name: `http://host.docker.internal:5173/src/main.tsx`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:5173/theme-init.js
  * Node Name: `http://host.docker.internal:5173/theme-init.js`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: Systemic


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

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Medium)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: http://host.docker.internal:5173/@react-refresh
  * Node Name: `http://host.docker.internal:5173/@react-refresh`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// TODO: rename these field`
  * Other Info: `The following pattern was used: \bTODO\b and was detected in likely comment: "// TODO: rename these fields to something more meaningful.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/@react-refresh
  * Node Name: `http://host.docker.internal:5173/@react-refresh`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ogic is copy-pasted from similar logic in th`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 2 times, the first in likely comment: "// This logic is copy-pasted from similar logic in the DevTools backend.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/@vite/client
  * Node Name: `http://host.docker.internal:5173/@vite/client`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` `\0`, a convention from the rollup ecosyste`
  * Other Info: `The following pattern was used: \bFROM\b and was detected in likely comment: "/**
* Plugins that use 'virtual modules' (e.g. for helper functions), prefix the
* module ID with `\0`, a convention from the ro", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/@radix-ui_react-dropdown-menu.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/@radix-ui_react-dropdown-menu.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `nstance, prevent it from overflowing the cli`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 5 times, the first in likely comment: "/**
* Provides data that allows you to change the size of the floating element —
* for instance, prevent it from overflowing the", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/@simplewebauthn_browser.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/@simplewebauthn_browser.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/**
* Convert from a Base64URL-encoded`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 4 times, the first in likely comment: "/**
* Convert from a Base64URL-encoded string to an Array Buffer. Best used when converting a
* credential ID from a JSON string", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/@simplewebauthn_browser.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/@simplewebauthn_browser.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `rd manager that the user just signed in with`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 5 times, the first in likely comment: "/**
* Begin authenticator "registration" via WebAuthn attestation
*
* @param optionsJSON Output from **@simplewebauthn/server**'", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/@tanstack_react-query.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/@tanstack_react-query.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `lbacks or functions where reading the latest `
  * Other Info: `The following pattern was used: \bWHERE\b and was detected in likely comment: "/**
	* Imperative (non-reactive) way to retrieve data for a QueryKey.
	* Should only be used in callbacks or functions where rea", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/@tanstack_react-query.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/@tanstack_react-query.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `les/@tanstack/react-query/build/modern/QueryC`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected 53 times, the first in likely comment: "//#region node_modules/@tanstack/react-query/build/modern/QueryClientProvider.js", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `dist/esm/icons/book-user.mjs`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 31 times, the first in likely comment: "//#region node_modules/lucide-react/dist/esm/icons/book-user.mjs", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `dist/esm/icons/list-todo.mjs`
  * Other Info: `The following pattern was used: \bTODO\b and was detected in likely comment: "//#region node_modules/lucide-react/dist/esm/icons/list-todo.mjs", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eact/dist/esm/icons/bug-off.mjs`
  * Other Info: `The following pattern was used: \bBUG\b and was detected 3 times, the first in likely comment: "//#region node_modules/lucide-react/dist/esm/icons/bug-off.mjs", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ist/esm/icons/lasso-select.mjs`
  * Other Info: `The following pattern was used: \bSELECT\b and was detected in likely comment: "//#region node_modules/lucide-react/dist/esm/icons/lasso-select.mjs", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/lucide-react.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `sm/icons/arrow-down-from-line.mjs`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 6 times, the first in likely comment: "//#region node_modules/lucide-react/dist/esm/icons/arrow-down-from-line.mjs", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/react-hook-form.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/react-hook-form.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` nested structures, where it would become inc`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected in likely comment: "/**
* This custom hook allows you to access the form context. useFormContext is intended to be used in deeply nested structures,", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/react-hook-form.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/react-hook-form.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `access only control from context.
*/`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 2 times, the first in likely comment: "/**
* @internal Internal hook to access only control from context.
*/", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/react-router-dom.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/react-router-dom.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `*
	* Access a value from the context. If no `
  * Other Info: `The following pattern was used: \bFROM\b and was detected in likely comment: "/**
	* Access a value from the context. If no value has been set for the context,
	* it will return the context's `defaultValue`", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/react-router-dom.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/react-router-dom.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `, will
	* cause the user agent to ignore the`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "/**
	* RegExp to match domain-value in RFC 6265 sec 4.1.1
	*
	* domain-value      = <subdomain>
	*                     ; defined", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/**
			* User Select
			* @see ht`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "/**
			* User Select
			* @see https://tailwindcss.com/docs/user-select
			*/", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `m baseConfig Config where other config will b`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected in likely comment: "/**
* @param baseConfig Config where other config will be merged into. This object will be mutated.
* @param configExtension Par", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `t-bottom-left
			* @todo class group will be`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 2 times, the first in likely comment: "/**
			* Inset Inline Start
			* @see https://tailwindcss.com/docs/top-right-bottom-left
			* @todo class group will be renamed ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/tailwind-merge.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `this file is copied from https://github.com/`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 3 times, the first in likely comment: "/**
* The code in this file is copied from https://github.com/lukeed/clsx and modified to suit the needs of tailwind-merge bette", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/zod.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/zod.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` and answers with a later one — so the throw `
  * Other Info: `The following pattern was used: \bLATER\b and was detected in likely comment: "/** A predicate that hands back a thenable is an async check reached synchronously, and the interpreter throws `$ZodAsyncError` ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/zod.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/zod.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `',
*       path: [ 'username' ],
*       message`
  * Other Info: `The following pattern was used: \bUSERNAME\b and was detected in likely comment: "/** Format a ZodError as a human-readable string in the following form.
*
* From
*
* ```ts
* ZodError {
*   issues: [
*     {
* ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/zod.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/zod.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `` currently answers from: the one the caller`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 12 times, the first in likely comment: "/**
* Whichever object a def's `shape` currently answers from: the one the caller passed until the first read, the frozen copy a", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/zod.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/zod.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `l that thunk from a user callback — rest and`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 3 times, the first in likely comment: "/** Marks the thunk `_catch` synthesises for a constant catch value. `Function.length` cannot tell that thunk from a user callba", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/node_modules/.vite/deps/zod.js%3Fv=f59f3bcc
  * Node Name: `http://host.docker.internal:5173/node_modules/.vite/deps/zod.js (v)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `produces
* a parser where `new Function` is u`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 3 times, the first in likely comment: "/**
* Install an already-generated parser as a schema's fast path. Returns a clone; the original is
* unchanged.
*
* The parser ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/App.tsx
  * Node Name: `http://host.docker.internal:5173/src/App.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// true from the persisted store`
  * Other Info: `The following pattern was used: \bFROM\b and was detected in likely comment: "// true from the persisted store. The persisted value can be stale (e.g.,", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/App.tsx
  * Node Name: `http://host.docker.internal:5173/src/App.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `the first protected query would`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "// access/refresh cookies expired) and the first protected query would", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/components/layout/Sidebar.tsx
  * Node Name: `http://host.docker.internal:5173/src/components/layout/Sidebar.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// The Administrator role holds every pe`
  * Other Info: `The following pattern was used: \bADMINISTRATOR\b and was detected in likely comment: "// The Administrator role holds every permission, so admins see all.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/components/layout/Sidebar.tsx
  * Node Name: `http://host.docker.internal:5173/src/components/layout/Sidebar.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `with the view-only `admin.read` or its area p`
  * Other Info: `The following pattern was used: \bADMIN\b and was detected 2 times, the first in likely comment: "// visible with the view-only `admin.read` or its area permission.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/components/shared/Banner.tsx
  * Node Name: `http://host.docker.internal:5173/src/components/shared/Banner.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/**
* Unified user-facing message bann`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "/**
* Unified user-facing message banner.
*
* Replaces ~16 distinct inline error/success/info/warning styles that were
* scatter", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/components/shared/DemoInbox.tsx
  * Node Name: `http://host.docker.internal:5173/src/components/shared/DemoInbox.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `* Rendered on pages where an anonymous demo v`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected in likely comment: "/**
* Demo-mode email inbox.
*
* Rendered on pages where an anonymous demo visitor is waiting for an email
* (post-registration,", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/hooks/useApi.ts
  * Node Name: `http://host.docker.internal:5173/src/hooks/useApi.ts`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `rontend has several query keys that read API-`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "/**
* Cross-page cache invalidation for API keys.
*
* The frontend has several query keys that read API-key lists:
*
*   - `['my", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/lib/api.ts
  * Node Name: `http://host.docker.internal:5173/src/lib/api.ts`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/ then handles each query's 401 as a normal e`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "// then handles each query's 401 as a normal error.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/lib/api.ts
  * Node Name: `http://host.docker.internal:5173/src/lib/api.ts`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// Endpoints where a 401 is an *expect`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected in likely comment: "// Endpoints where a 401 is an *expected* credential failure (e.g. a wrong", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/lib/api.ts
  * Node Name: `http://host.docker.internal:5173/src/lib/api.ts`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `oken (e.g. on a 403 from the CSRF gate, or
*`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 3 times, the first in likely comment: "/** Drop the cached CSRF token (e.g. on a 403 from the CSRF gate, or
* after a hard sign-out) so the next unsafe request re-boot", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/lib/api.ts
  * Node Name: `http://host.docker.internal:5173/src/lib/api.ts`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `show a toast so the user understands what ha`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 2 times, the first in likely comment: "// Soft UX: show a toast so the user understands what happened, then", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/pages/DashboardPage.tsx
  * Node Name: `http://host.docker.internal:5173/src/pages/DashboardPage.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// /api/admin/stats requires admi`
  * Other Info: `The following pattern was used: \bADMIN\b and was detected in likely comment: "// /api/admin/stats requires admin.read (or any admin capability via", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/pages/DashboardPage.tsx
  * Node Name: `http://host.docker.internal:5173/src/pages/DashboardPage.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// the Administrator role) — enable for `
  * Other Info: `The following pattern was used: \bADMINISTRATOR\b and was detected in likely comment: "// the Administrator role) — enable for view-only operators too.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/pages/ProfilePage.tsx
  * Node Name: `http://host.docker.internal:5173/src/pages/ProfilePage.tsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `on too and send the user to`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "// auth cookies — drop the local session too and send the user to", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:5173/src/stores/toastStore.ts
  * Node Name: `http://host.docker.internal:5173/src/stores/toastStore.ts`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` transient feedback from outside React
* (ev`
  * Other Info: `The following pattern was used: \bFROM\b and was detected in likely comment: "/**
* Static-style helpers for showing transient feedback from outside React
* (event handlers, async callbacks, etc.). No hook ", see evidence field for the suspicious comment/snippet.`


Instances: 41

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

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


Instances: 1

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


Instances: 2

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://host.docker.internal:5173/api/oauth2/csrf-token
  * Node Name: `http://host.docker.internal:5173/api/oauth2/csrf-token`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/api/oauth2/csrf-token
  * Node Name: `http://host.docker.internal:5173/api/oauth2/csrf-token`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:5173/api/oauth2/csrf-token
  * Node Name: `http://host.docker.internal:5173/api/oauth2/csrf-token`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8001/api/auth/expired-password/change
  * Node Name: `http://host.docker.internal:8001/api/auth/expired-password/change ()({email,current_password,new_password})`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8001/api/email/resend-verification
  * Node Name: `http://host.docker.internal:8001/api/email/resend-verification ()({email})`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8001/api/email/resend-verification
  * Node Name: `http://host.docker.internal:8001/api/email/resend-verification ()({email})`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution



### Reference


* [ https://owasp.org/wstg ](https://owasp.org/wstg)



#### Source ID: 1


