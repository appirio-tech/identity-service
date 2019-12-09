
function isUrl(value) {
  var URL_PATTERN = /^(https?:\/\/)?((([a-z\d]([a-z\d-]*[a-z\d])*)\.)+[a-z]{2,}|((\d{1,3}\.){3}\d{1,3}))(\:\d+)?(\/[-a-z\d%_.~+]*)*(\?[;&a-z\d%_.~+=-]*)?(\#[-a-z\d_]*)?/i;
  return URL_PATTERN.test(value);
};

function validateUrl(url) {
  if (!isUrl(url)) {
    return false;
  }
  
  var parser = document.createElement('a');
  parser.href = url;
  var hostname = parser.hostname.toLowerCase();
  
  return hostname.endsWith('topcoder.com') || hostname.endsWith('topcoder-qa.com') || hostname.endsWith('topcoder-dev.com');
};

function redirect(to) {
    if(!to) {
        return;
    }
    if(!validateUrl(to)) {
    	alert('The URL to redirect is invalid.')
    	return;
    }
    location.href = to;
};

function parseQuery(query) {
	var params = {};
	if(!query)
		return params;
	var kvs = query.split('&');
	for(var i=0; i<kvs.length; i++) {
		if(kvs[i].indexOf('=')<0) {
			params[decodeURIComponent(kvs[i])] = null;
			continue;
		}
		var pair = kvs[i].split('=');
		params[decodeURIComponent(pair[0])] = decodeURIComponent(pair[1]);
	}
    return params;
};

function getQueryParameters() {
	if(1 >= window.location.search.length) {
		return {};
	}
	return parseQuery(window.location.search.substring(1));
};

function getHashParameters() {
	if(1 >= window.location.hash.length) {
		return {};
	}
	return parseQuery(window.location.hash.substring(1));
};