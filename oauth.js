// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

window.onload = function () {
	const clientId = '1162142240874567'; //<-------------------------- clientId from https://app.asana.com/0/developer-console/app/[clientID]
	const clientSecret = '46ca57036c9b902a542440948e7aec12'; //<-------------------------- Client secret from https://app.asana.com/0/developer-console/app/[clientID]
	const chromeExtensionId = chrome.runtime.id; //<------- redirect_uri should be added on the same page https://app.asana.com/0/developer-console/app/[clientID]
	//it should look like https://[chromeExtensionId].chromiumapp.org/provider_cb

	function addToTextArea(text) {
		document.getElementById('userInfoTextArea').textContent = document.getElementById('userInfoTextArea').textContent + '\n' + text;
	}

	addToTextArea('extensionId:' + chrome.runtime.id);

	function generateRandomString() {
		var array = new Uint32Array(56 / 2);
		window.crypto.getRandomValues(array);
		return Array.from(array, dec2hex).join('');
	}

	function dec2hex(dec) {
		return ('0' + dec.toString(16)).substr(-2)
	}

	function sha256(plain) { // returns promise ArrayBuffer
		const encoder = new TextEncoder();
		const data = encoder.encode(plain);
		return window.crypto.subtle.digest('SHA-256', data);
	}

	function base64urlencode(a) {
		// Convert the ArrayBuffer to string using Uint8 array. btoa takes chars from 0-255 and base64 encodes.
		// Then convert the base64 encoded to base64url encoded. (replace + with -, replace / with _, trim trailing =)
		return btoa(String.fromCharCode.apply(null, new Uint8Array(a)))
		.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	}

	async function pkce_challenge_from_verifier(v) {
		let hashed = await sha256(v);
		let base64encoded = base64urlencode(hashed);
		return base64encoded;
	}

	//initial function to get accessToken from Asana - it's executed during window onload 
	function getToken(code_challenge) {
		addToTextArea('code_challenge:' + code_challenge);
		let oauth2Url = 'https://app.asana.com/-/oauth_authorize?response_type=code&client_id=1162142240874567&code_challenge_method=S256&code_challenge=' + code_challenge + '&redirect_uri=https%3A%2F%2F' + chromeExtensionId + '.chromiumapp.org%2Fprovider_cb&state=init';
		chrome.identity.launchWebAuthFlow({
			'url': oauth2Url,
			'interactive': true
		},
			function (redirect_url) {
			try {
				addToTextArea('redirect_url:' + redirect_url);
				let url = new URL(redirect_url);
				let urlParams = new URLSearchParams(url.search.slice(1));
				if (!urlParams.has('code')) {
					addToTextArea('NO OAuth2 code in the response');
					throw 'NO code in the response';
				}
				const code = urlParams.get('code');
				addToTextArea('code:' + code);

				var formData = {};
				formData['client_id'] = clientId;
				formData['client_secret'] = clientSecret;
				formData['code'] = code;
				formData['grant_type'] = 'authorization_code';
				formData['code_verifier'] = code_verifier;
				formData['redirect_uri'] = 'https://' + chromeExtensionId + '.chromiumapp.org/provider_cb';

				addToTextArea('JSON.stringify(formData):' + JSON.stringify(formData));
				const searchParams = Object.keys(formData).map((key) => {
						return encodeURIComponent(key) + '=' + encodeURIComponent(formData[key]);
					}).join('&');
				addToTextArea('searchParams:' + searchParams);

				fetch('https://app.asana.com/-/oauth_token', {
					method: 'POST',
					headers: {
						'Content-type': 'application/x-www-form-urlencoded'
					},
					body: searchParams
				}).then((tokenResponse) => tokenResponse.json()).then((data) => {
					addToTextArea('Request succeeded with JSON response:' + JSON.stringify(data));
					console.log('Request succeeded with JSON response:' + JSON.stringify(data));
					//saving access token to use with API calls 
					document.getElementById("accessToken").setAttribute("value", data.access_token);
					//saving refresh token to use when current expires
					document.getElementById("refreshToken").setAttribute("value", data.refresh_token);
					//saving user git to use for getUserList call 
					document.getElementById("userGid").setAttribute("value", data.data.gid);
					//enable getUserINfo button  
					document.getElementById("getUserInfo").removeAttribute("disabled");
				});

			} catch (err) {
				addToTextArea('Redirect_url Err:' + err);
			}
		});
	}
	
	// function to get current user from Asana API, it's registered to onclick event for the getUserInfo button 
	async function getCurrentUser() {
		//get div with saved accessToken from getToken call
		let div = document.getElementById("accessToken");
		addToTextArea('getCurrentUser.div.accessToken:' + div);
		//get actual accessToken 
		const accessToken = div.getAttribute("value");
		addToTextArea('getCurrentUser.accessToken:' + accessToken);
		
		div = document.getElementById("userGid"); 
		addToTextArea('getCurrentUser.div.userGid:' + div);
		//get user gid
		const userGid = div.getAttribute("value");
		addToTextArea('getCurrentUser.userGid:' + userGid);
		
		if (accessToken && accessToken.length > 0 && userGid && userGid.length > 0) {
			const apiUserTasksList = 'https://app.asana.com/api/1.0/users/' + userGid;
			addToTextArea('apiUserTasksList:' + apiUserTasksList);
			console.log('apiUserTasksList:' + apiUserTasksList);
			console.log("Authorization:Bearer " + accessToken);

			const userInfoResponse = await fetch(apiUserTasksList, {
					method: 'GET',
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + accessToken
					}
				});
			const userInfo = await userInfoResponse.json();
			addToTextArea('Request succeeded with JSON response:' + JSON.stringify(userInfo));
			console.log('Request succeeded with JSON response:' + JSON.stringify(userInfo));
			return userInfo;
		} else {
			addToTextArea('accessToken is not set, please wait...');
			return null;
		}
	}

	// function to get user list from Asana API
	async function getUserList() {
		//get div with saved accessToken from getToken call
		let div = document.getElementById("accessToken");
		addToTextArea('getUserList.div.accessToken:' + div);
		//get actual accessToken 
		const accessToken = div.getAttribute("value");
		addToTextArea('getUserList.accessToken:' + accessToken);
		
		if (accessToken && accessToken.length > 0) {
			const userList = 'https://app.asana.com/api/1.0/users/?workspace=156742922891414';
			addToTextArea('apiUserTasksList:' + userList);

			const userInfoResponse = await fetch(userList, {
					method: 'GET',
					headers: {
						"Accept": "application/json",
						"Authorization": "Bearer " + accessToken
					}
				});
			const userInfo = await userInfoResponse.json();
			const data = userInfo.data;
			addToTextArea('Request succeeded with JSON response:' + JSON.stringify(data));
			console.log('Request succeeded with JSON response:' + JSON.stringify(userInfo));
			
			console.log(userInfo);

			data.forEach(x=> {
				console.log(x.name)
			})

			for (var key in userInfo) {
    			if (userInfo.hasOwnProperty(key)) {
        			console.log(JSON.stringify(userInfo[key]));
        			//document.getElementById("myDivClass").innerHTML = JSON.stringify(userInfo[key]);
    			}
			}

			return userInfo;
		} else {
			addToTextArea('accessToken is not set, please wait...');
			return null;
		}
	}
	

	let code_verifier = generateRandomString();
	addToTextArea('code_verifier:' + code_verifier);
	pkce_challenge_from_verifier(code_verifier).then(code_challenge => getToken(code_challenge));

	document.querySelector('button').addEventListener('click', function () {
		getUserList();
	});
};

//const apiUserTasksList = 'https://app.asana.com/api/1.0/users?workspace=156742922891414';
//const apiUserTasksList = 'https://app.asana.com/api/1.0/users/'+ data.data.gid +'/user_task_list?workspace=156742922891414&opt_fields=id,created_at,modified_at,name,notes,assignee,completed:‘true’,assignee_status,completed_at,due_on,due_at,projects'
//const apiUserTasksList = 'https://app.asana.com/api/1.0/workspaces/156742922891414/tasks/search?created_at.after=2015-02-11T21:00:34.889Z';
//const apiUserTasksList = 'https://app.asana.com/api/1.0/user_task_lists/1161935722713876/tasks?opt_fields=id,created_at,name,assignee,completed:‘true’,completed_at,due_on,due_at,projects' ;
//const apiUserTasksList = 'https://app.asana.com/api/1.0/users/'+ data.data.gid +'/user_task_list?workspace=156742922891414' ;
//const apiUserTasksList = 'https://app.asana.com/api/1.0/users/' + data.data.gid;

