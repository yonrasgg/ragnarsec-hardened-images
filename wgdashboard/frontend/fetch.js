// SPDX-License-Identifier: Apache-2.0
// Derived from WGDashboard v4.3.4 (WGDashboard contributors).

import {DashboardConfigurationStore} from "@/stores/DashboardConfigurationStore.js";
import router from "@/router/router.js";
const getHeaders = () => {
	let headers = {
		"Content-Type": "application/json"
	}
	try{
		const store = DashboardConfigurationStore();
		const crossServer = store.getActiveCrossServer();
		if (crossServer){
			headers['wg-dashboard-apikey'] = crossServer.apiKey
			if (crossServer.headers){
				for (let header of Object.values(crossServer.headers)){
					if (header.key && header.value && !Object.keys(headers).includes(header.key)){
						headers[header.key] = header.value
					}
				}
			}
		}
	}catch (e) {

	}


	return headers
}

export const getUrl = (url) => {
	try{
		const store = DashboardConfigurationStore();
		const apiKey = store.getActiveCrossServer();
		if (apiKey){
			return `${apiKey.host}${url}`
		}
	}catch (e){}
	if (import.meta.env.MODE === 'development') {
		return url;
	}
	// const appPrefix = window.APP_PREFIX || '';
	return `./.${url}`;
}

const requestJson = async (url, options, callback) => {
	try {
		const response = await fetch(url, {headers: getHeaders(), ...options});
		if (response.status === 401) {
			DashboardConfigurationStore().newMessage("WGDashboard", "Sign in session ended, please sign in again", "warning");
			await router.push({path: '/signin'});
			return;
		}
		if (!response.ok) {
			const message = response.status === 403
				? "Access denied for this operation"
				: `Request failed (HTTP ${response.status})`;
			DashboardConfigurationStore().newMessage("WGDashboard", message, "warning");
			return;
		}
		const data = await response.json();
		if (callback) await callback(data);
	} catch (error) {
		console.error("WGDashboard request failed", error);
		DashboardConfigurationStore().newMessage("WGDashboard", "Could not complete the request", "warning");
	}
};

export const fetchGet = async (url, params=undefined, callback=undefined) => {
	const urlSearchParams = new URLSearchParams(params);
	await requestJson(`${getUrl(url)}?${urlSearchParams.toString()}`, {}, callback);
};

export const fetchPost = async (url, body, callback) => {
	await requestJson(getUrl(url), {method: "POST", body: JSON.stringify(body)}, callback);
};

export const fetchPut = async (url, body, callback) => {
	await requestJson(getUrl(url), {method: "PUT", body: JSON.stringify(body)}, callback);
};

export const fetchDelete = async (url, body, callback) => {
	await requestJson(getUrl(url), {method: "DELETE", body: JSON.stringify(body)}, callback);
};
