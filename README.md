# adwords-scripts-aws-s3

Example of fetch files from AWS S3 from within AdWords Scripts.

This solution provides example code for fetching files from S3 using the ES5 environment within AdWords Scripts.

## Usage

1. Copy the code from `s3-example.js` and paste it into your AdWords Script.
1. Initialize an `S3` object:

   ```javascript
   var s3 = new S3('<region>', '<access_key_id>', '<access_secret>');
   ```
1. Once initialized, to make an authorized `GET` request:

   ```javascript
   var response = s3.fetch('<AWS URL>');
   ```
   
The `response` object is of class [HttpResponse](https://developers.google.com/apps-script/reference/url-fetch/http-response). 

To determine success therefore, call `response.getResponseCode()` to check for a status of `200`, before obtaining the content with [one of the other methods listed](https://developers.google.com/apps-script/reference/url-fetch/http-response).
