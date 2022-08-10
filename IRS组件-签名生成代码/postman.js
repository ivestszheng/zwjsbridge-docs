
var accessKey = "xxx"; //替换成自己的ak
var secret="xxxx"; //替换成自己的sk

var path = pm.request.url.getPath();
var query=pm.request.url.query;
var queryArray=[];
for(index in query.members){
    var member= query.members[index];
    var value = member["value"];
    if(member["value"]==null){
        value = ""
    }
    var queryKeyValue = encodeURIComponent(member["key"])+"="+encodeURIComponent(value);
    queryArray.push(queryKeyValue);
}
queryArray.sort();
var queryString = queryArray.join("&");

var date = (new Date()).toGMTString();
var singString = pm.request.method+"\n"+path+"\n"+queryString+"\n"+accessKey+"\n"+date+"\n";
var hash = CryptoJS.HmacSHA256(singString, secret);
var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

pm.environment.set("X-BG-HMAC-ACCESS-KEY",accessKey);
pm.environment.set("X-BG-HMAC-SIGNATURE",hashInBase64);
pm.environment.set("X-BG-HMAC-ALGORITHM","hmac-sha256");
pm.environment.set("X-BG-DATE-TIME",date);
