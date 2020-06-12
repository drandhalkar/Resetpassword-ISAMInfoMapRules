/*********************************************************************
 *   Licensed Materials - Property of IBM
 *   (C) Copyright IBM Corp. 2016. All Rights Reserved
 *
 *   US Government Users Restricted Rights - Use, duplication, or
 *   disclosure restricted by GSA ADP Schedule Contract with
 *   IBM Corp.
 *********************************************************************/

importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importPackage(Packages.com.ibm.security.access.scimclient);

importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.com.ibm.security.access.httpclient.Headers);

IDMappingExtUtils.traceString("entry iam_PasswordReset_CollectPassword.js");

var errors = [];
var missing = [];
var rc = true;

var first = false;

if (state.get("first_collectPassword") == null) {
  first = true;
  state.put("first_collectPassword", "false");
  rc = false;
}

var scimConfig = context.get(Scope.SESSION, "urn:ibm:security:asf:policy", "scimConfig");

var id = context.get(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username");
IDMappingExtUtils.traceString("iam_PasswordReset_CollectPassword username: "+id);

/*
 * Check that the passwords are present and match.
 */

function utf8decode(value) {
  if (value == null || value.length == 0) return "";
  return decodeURIComponent(escape(value));
}

var password = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "password"));
var passwordConfirm = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "passwordConfirm"));

IDMappingExtUtils.traceString("iam_PasswordReset_CollectPassword: "+password);


if (null == password || password.length == 0) {
  missing.push("password");
  rc = false;
} else if (password != passwordConfirm) {
  errors.push("Passwords do not match.");
  rc = false;
}


/*
* ISIM reset password code
*/


var htPost = new HttpResponse();
var hr = new HttpResponse();
var params = new Parameters();
var headers = new Headers();

//POST params builder using example from OAuth Pre-Token Mapping rule
params.addParameter("j_username", "itim service account");
params.addParameter("j_password", "xxxxxxx");

//Set headers
headers.addHeader("Content-Type","application/x-www-form-urlencoded");

// SSL httpPost - be sure to add certificate to rt trust store
// This assumes default trust store (util.httpClient.defaultTrustStore in Advanced Configuration panel)
//hr = HttpClient.httpPost("http://172.24.113.8:9080/itim/j_security_check", param);
htPost = HttpClient.httpGet("http://172.24.113.8:9080/itim/restpwd");
IDMappingExtUtils.traceString("Post response code: " + htPost.getCode());
IDMappingExtUtils.traceString("Post response body: " + htPost.getBody());

if (htPost != null && htPost.getCode() == 200) {
    IDMappingExtUtils.traceString("###ISIM reset completed successfully...");
} else {
    IDMappingExtUtils.traceString("#### Error in ISIM reset");
	errors.push("Error in ISIM reset.");
	rc=false;
}


/*
 * Update the password and PUT the JSON back to the SCIM API endpoint.
 */


/*
 * Handle errors.
 */

function buildErrorString(errors) {
  var errorString = "";

  if (missing.length != 0) {
    errorString += "Missing required field(s): "+missing;
  }

  for (var error in errors) {
    if (errorString != "") errorString += "   ";
    errorString += "Error: "
    errorString += errors[error];
  }
  return errorString;
}

var errorString = buildErrorString(errors);
if (!first && errorString.length != 0) {
  macros.put("@ERROR_MESSAGE@", errorString);
}

if (rc == true) {
  /*
   * Set these values in the credential so they can be displayed on the success page.
   */
  context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", id);
  context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "firstName", id);
}

/*
 * Done!
 */

success.setValue(rc);

IDMappingExtUtils.traceString("exit iam_PasswordReset_CollectPassword.js");
