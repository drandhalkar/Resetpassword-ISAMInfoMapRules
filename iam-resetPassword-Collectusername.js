


importPackage(Packages.com.ibm.security.access.scimclient);
importClass(Packages.com.ibm.security.access.recaptcha.RecaptchaClient);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

IDMappingExtUtils.traceString("iam-collectusername.js");

var errors = [];
var missing = [];
var rc = true;

/*
 * Load the email address and perform some basic verification.
 */

function utf8decode(value) {
  if (value == null || value.length == 0) return "";
  return decodeURIComponent(escape(value));
}

var email = utf8decode(context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username"));
 IDMappingExtUtils.traceString("collectusername.Read usenrmae: "+email);
if (email != "") {
   IDMappingExtUtils.traceString("collectusername.username exist: "+email);

  email = ""+email;

  if (email != "") {
    if (email.length > 5) {
      IDMappingExtUtils.traceString("Email is okay");
      context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "email", email);
      context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", email);
	  //context.set(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username", email);
    } else {
      errors.push("Email is invalid (too short)");
      rc = false;
    }
    macros.put("@EMAIL@", email);
  } else {
    missing.push("email");
    rc =false;
  }
} else {
  rc = false;
}

/*
 * Handle errors
 */

function buildErrorString(errors) {
  var errorString = "";

  if (missing.length != 0) {
    errorString += "Missing required field(s): "+missing;
  }

  for (var error in errors) {
    if (errorString != "") errorString += "<br/>";
    errorString += "Error: "
    errorString += errors[error];
  }
  return errorString;
}


var errorString = buildErrorString(errors);
if (errorString.length != 0) {
  macros.put("@ERROR_MESSAGE@", errorString);
}

/*
 * Done!
 */

success.setValue(rc);

IDMappingExtUtils.traceString("exit iam-collectusername.js");
