/**
 * An implementation of the AWS request v4 for retrieving files from S3, for use
 * in AdWords Scripts.
 *
 * Based on :
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 */

function s3example() {
  // Basic example, grabbing a CSV file from Amazon and writing to a Google Sheet
  
  // Input CSV URL on Amazon S3
  var inputCsvUrl = 'https://s3.us-east-2.amazonaws.com/example_bucket/test.csv';
  
  // Output spreadsheet in Google Sheets, for ingestion by other Google Apps and services.
  var outputSpreadsheetUrl ='https://docs.google.com/spreadsheets/d/...../edit';
  
  // Create S3 client, using credentials.
  var s3 = new S3(
      'us-east-2', 'AKIAI2EA5TCTXVP6PG3Q',
      'gs+TCMuAa+SRu1oQG+Q0kXhCnxghjG51HJ65L99f');
  var response = s3.fetch(inputCsvUrl);

  if (response.getResponseCode() === 200) {
    var csv = Utilities.parseCsv(response.getContentText());
    var ss = SpreadsheetApp.openByUrl(outputSpreadsheetUrl);
    var s = ss.getActiveSheet();
    s.getRange(1, 1, csv.length, csv[0].length).setValues(csv);
  } else {
    // ... Do something with error
    Logger.log(response);
  }
}

/**
 * Creates a client for making authenticated requests to the Amazon S3 service.
 *
 * @param {string} region The AWS region, e.g. "us-east-1".
 * @param {string} accessKeyId
 * @param {string} accessSecret
 * @return {!Object} the client object
 */
function S3(region, accessKeyId, accessSecret) {
  this.region = region;
  this.accessKeyId = accessKeyId;
  this.accessSecret = accessSecret;
  this.versionString = 'aws4_request';
  this.service = 's3';
  this.date = new Date();
  this.signingKey = this._createSigningKey();
  this.credential = this._getCredential();
  this.headers = {
    'x-amz-content-sha256': this._getHexSha256Hash(''),
    'x-amz-date': this._getTimeStampISO8601Format()
  };
  this.uriRegex = /^http(?:s|):\/\/[^\/]+([^\?]*)/;
  this.hostRegex = /^http(?:s|):\/\/([^\/]+)/;
}

/**
 * Retrieves a URL using a GET request.
 *
 * @param {string} url The URL of the resource.
 * @return {!HttpResponse} The response {@see https://developers.google.com/apps-script/reference/url-fetch/http-response)
 */
S3.prototype.fetch = function(url) {
  var canonicalRequest = this._createCanonicalRequest(url);
  var stringToSign = this._getStringToSign(canonicalRequest);
  var signature = this._getHexHmacSha256(this.signingKey, stringToSign);
  var authorization = this._getAuthorizationHeader(signature);

  var headers = {Authorization: authorization};
  var headerKeys = Object.keys(this.headers);
  headerKeys.forEach(function(k) {
    headers[k] = this.headers[k];
  }.bind(this));
  var params = {headers: headers, muteHttpExceptions: true};
  return UrlFetchApp.fetch(url, params);
};

S3.prototype._createCanonicalRequest = function(url) {
  return [
    'GET', this._getCanonicalUri(url), this._getCanonicalQueryString(url),
    this._getCanonicalHeaders(url), this._getSignedHeaders(),
    this._getHexSha256Hash('')
  ].join('\n');
};

S3.prototype._getCanonicalUri = function(url) {
  var matches = this.uriRegex.exec(url);
  return matches[1] || '/';
};

S3.prototype._getCanonicalQueryString = function(url) {
  var paramsIndex = url.indexOf('?');
  if (paramsIndex === -1 || paramsIndex === url.length - 1) {
    return '';
  }
  var paramsString = url.substring(paramsIndex + 1);
  var params = paramsString.split('&').map(function(p) {
    var parts = p.split('=');
    return [parts[0], parts[1] || ''];
  });
  params.sort(this._pairKeySort);
  return params
      .map(function(p) {
        return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]);
      })
      .join('&');
};

S3.prototype._getCanonicalHeaders = function(url) {
  var matches = this.hostRegex.exec(url);
  var host = matches[1];

  var canonical = [['Host', host]];
  var keys = Object.keys(this.headers);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    canonical.push([key, this.headers[key]]);
  }
  var list = canonical.map(function(p) {
    return p[0].toLowerCase() + ':' + p[1].trim() + '\n';
  });
  list.sort();
  return list.join('');
};

S3.prototype._getSignedHeaders = function() {
  var headers = Object.keys(this.headers);
  var lcHdrs = headers.map(function(h) {
    return h.toLowerCase();
  });
  lcHdrs.push('host');
  lcHdrs.sort();
  return lcHdrs.join(';');
};

S3.prototype._getStringToSign = function(canonicalRequest) {
  return [
    'AWS4-HMAC-SHA256', this._getTimeStampISO8601Format(), this._getScope(),
    this._getHexSha256Hash(canonicalRequest)
  ].join('\n');
};

S3.prototype._getScope = function() {
  return [
    this._getYearDate(), this.region, this.service, this.versionString
  ].join('/');
};

S3.prototype._getAuthorizationHeader = function(signature) {
  return Utilities.formatString(
      'AWS4-HMAC-SHA256 Credential=%s,SignedHeaders=%s,Signature=%s',
      this._getCredential(), this._getSignedHeaders(), signature);
};

S3.prototype._pairKeySort = function(a, b) {
  if (a[0] < b[0]) {
    return -1;
  } else if (a[0] > b[0]) {
    return 1;
  }
  return 0;
};

S3.prototype._createSigningKey = function() {
  var dateKey = Utilities.computeHmacSha256Signature(
      this._getYearDate(), 'AWS4' + this.accessSecret);
  var dateRegionKey =
      Utilities.computeHmacSha256Signature(this._toBytes(this.region), dateKey);
  var dateRegionServiceKey = Utilities.computeHmacSha256Signature(
      this._toBytes(this.service), dateRegionKey);
  return Utilities.computeHmacSha256Signature(
      this._toBytes(this.versionString), dateRegionServiceKey);
};

S3.prototype._getCredential = function() {
  var date = this._getYearDate();
  return [
    this.accessKeyId, date, this.region, this.service, this.versionString
  ].join('/');
};

S3.prototype._getTimeStampISO8601Format = function() {
  return Utilities.formatDate(this.date, 'UTC', 'yyyyMMdd\'T\'HHmmSS\'Z\'');
};

S3.prototype._getYearDate = function() {
  return Utilities.formatDate(this.date, 'UTC', 'yyyyMMdd');
};

S3.prototype._toBytes = function(str) {
  return Utilities.newBlob(str).getBytes();
};

S3.prototype._getHexSha256Hash = function(payload) {
  var bytes =
      Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, payload);
  return this._bytesToHex(bytes);
};

S3.prototype._getHexHmacSha256 = function(key, value) {
  if (typeof value === 'string') {
    var data = this._toBytes(value);
  } else {
    var data = value;
  }
  var bytes = Utilities.computeHmacSha256Signature(data, key);
  return this._bytesToHex(bytes);
};

S3.prototype._bytesToHex = function(bytes) {
  return bytes
      .map(function(b) {
        var c = (b < 0 ? b + 256 : b).toString(16);
        return c.length === 1 ? '0' + c : c;
      })
      .join('');
};
