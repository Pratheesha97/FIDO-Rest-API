import './App.css';
import Button from "@material-ui/core/Button";
import React from "react";
import qs from "qs";
import {preformatGetAssertReq, preformatMakeCredReq, publicKeyCredentialToJSON} from "./helper/helperFunctions";

const axios = require('axios').default;

//start authentication API call
async function callStartAuth() {
    const body = {
        "username": "admin",
        "tenantDomain": "carbon.super",
        "storeDomain": "PRIMARY",
        "appId": "https://localhost:3000"
    }

    let headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ca932937-d24e-3156-80f6-940fa78b4415'
    };
    try {
        let response = await axios.post('https://localhost:9443/wso2/rest/v1/fido2/start-authentication', body,
            {headers})
        if (response.status == 200) {

            return response.data;
        }
    } catch (err) {
        alert(err.response.data.message)
    }

};

//finish authentication API call
async function finishAuth(body) {

    let headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Authorization': 'Basic X3VBdE5EcEFQazl2UUxEYkE3UktvYkdkSnRrYTo0d1B2VXAwcldXRTdsMEtiek95WmVidFBjeGdh'
        };

    let username = "admin";
    const grantType = "fido";
    const content = {
        grant_type: grantType,
        username: username,
        response: JSON.stringify(body)
    }

    try {
        let res = await axios.post('https://localhost:9443/oauth2/token', qs.stringify(content), { headers });
        if (res.status == 200) {
            console.log(res.data);
            return res;
        }
    } catch (err) {
        alert(err.res.data.message)
    }
}

//authenticate user with FIDO2
async function authenticate() {
    try {
        let callStart = await callStartAuth();
        let obj;
        if (callStart) {
            obj = JSON.parse(callStart);
            let reqOpt = obj.publicKeyCredentialRequestOptions;

            let publicKey = preformatGetAssertReq(reqOpt);

            let credVal = await navigator.credentials.get({
                publicKey: publicKey,
            })

            let responseOb = {
                requestId: obj.requestId,
                credential: credVal
            }

            let getAssertionResponse = publicKeyCredentialToJSON(responseOb.credential);

            let credential = {
                id: getAssertionResponse.id,
                response: getAssertionResponse.response,
                clientExtensionResults: getAssertionResponse.getClientExtensionResults,
                type: getAssertionResponse.type
            }
            responseOb.credential = credential;

            let final = await finishAuth(responseOb);

            if (final.status == 200) {
                alert("Authentication Successful!")
            }
        }
    } catch (err) {
        console.log(err)
    }
}

//start registration API call
async function startRegistration(username, appId) {
    let headers = {
        'Authorization': 'Bearer ca932937-d24e-3156-80f6-940fa78b4415',
        'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
    };
    let body = {appId: appId};

    try {
        let response = await axios.post(`https://localhost:9443/api/users/v2/me/webauthn/start-registration?appId=${appId}`,
            body, {headers: headers})
        if (response.status == 200) {
            return response.data;
        }
    } catch (err) {
        alert(err.response.data.message);
    }
}

//finish registration API call
async function finishRegistration(data) {

    let headers = {
        'Authorization': 'Bearer ca932937-d24e-3156-80f6-940fa78b4415',
        'Content-Type': 'application/json'
    };

    let body = data;
    try {
        let po = await axios.post(`https://localhost:9443/api/users/v2/me/webauthn/finish-registration`,
            body, {headers: headers})
        if (po.status == 200) {
            return po.data;
        }
    } catch (err) {
        alert(err.response.data.message);
    }
}

//register FIDO2 device for user
async function register() {

    let username = "admin";
    let appId = "https://localhost:3000";

    try {
        let startReg = await startRegistration(username, appId);

        if (startReg) {
            let reqOpt = startReg.publicKeyCredentialCreationOptions;
            let pk = preformatMakeCredReq(reqOpt);
            let cred = await navigator.credentials.create({
                publicKey: pk,
            });

            let responseOb = {
                requestId: startReg.requestId,
                credential: cred
            }

            let getAssertionResponse = publicKeyCredentialToJSON(responseOb.credential);

            let credential = {
                id: getAssertionResponse.id,
                response: {
                    attestationObject: getAssertionResponse.response.attestationObject,
                    clientDataJSON: getAssertionResponse.response.clientDataJSON
                },
                clientExtensionResults: getAssertionResponse.getClientExtensionResults,
                type: getAssertionResponse.type
            }

            responseOb.credential = credential;
            let challengeRes = JSON.stringify(responseOb)
            let final = await finishRegistration(challengeRes);
            if (final) {
                alert("Successfully Registered!");
            }
        }
    } catch (err) {
        alert(err.message);
    }
}

function App() {
    return (
        <div className="App" style={{display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh'}}>
            <Button variant="contained" color="primary" style={{margin: '10px'}}
                    onClick={(e) => authenticate()}>Authenticate </Button>
            <Button variant="contained" color="primary" style={{margin: '10px'}}
                    onClick={(e) => register()}> Register Device</Button>
        </div>
    );
}

export default App;
