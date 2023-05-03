const base64url = require('base64url');

/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
export let publicKeyCredentialToJSON = (pubKeyCred) => {
    if(pubKeyCred instanceof Array) {
        let arr = [];
        for(let i of pubKeyCred)
            arr.push(publicKeyCredentialToJSON(i));

        return arr
    }

    if(pubKeyCred instanceof ArrayBuffer) {
        return base64url(pubKeyCred)
    }

    if(pubKeyCred instanceof Object) {
        let obj = {};

        for (let key in pubKeyCred) {
            obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
        }

        return obj
    }

    return pubKeyCred
}

/**
 * Decodes arrayBuffer required fields.
 */
export let preformatGetAssertReq = (getAssert) => {
    getAssert.challenge = base64url.toBuffer(getAssert.challenge);

    for(let allowCred of getAssert.allowCredentials) {
        allowCred.id = base64url.toBuffer(allowCred.id);
    }

    return getAssert
}

/**
 * Decodes arrayBuffer required fields.
 */
export let preformatMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64url.toBuffer(makeCredReq.challenge);
    makeCredReq.user.id = base64url.toBuffer(makeCredReq.user.id);
    if(makeCredReq.excludeCredentials){
       makeCredReq.excludeCredentials.forEach(exCredential =>{
           exCredential.id=base64url.toBuffer(exCredential.id);
       });
    }
    return makeCredReq
}
