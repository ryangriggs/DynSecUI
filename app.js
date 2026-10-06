(() => {
"use strict";
const APP_VERSION="1.0.2";
const CONTROL="$CONTROL/dynamic-security/v1", RESPONSE=CONTROL+"/response";
const ACL_TYPES=["publishClientSend","publishClientReceive","subscribeLiteral","subscribePattern","unsubscribeLiteral","unsubscribePattern"];
const DEFAULT_TOPIC_FILTERS=["#","$SYS/#"];
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let mqttClient=null, activeConn=null, pending=[], trafficLog=[], mutedLogTopics=new Set(), logRenderPending=false, topicRenderPending=false, selectedTopic=null;
let topicFilters=loadTopicFilters(), topicMessages=new Map(), state={clients:[],groups:[],roles:[],defaults:{},anonymousGroup:null};

function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function toast(msg,err=false){const e=$("#toast");e.textContent=msg;e.className=err?"show error":"show";clearTimeout(e._t);e._t=setTimeout(()=>e.className="",3500);}
function saved(){try{return JSON.parse(localStorage.getItem("dynsec.connections")||"[]")}catch{return []}}
function saveConns(v){localStorage.setItem("dynsec.connections",JSON.stringify(v))}
function loadTopicFilters(){try{const value=localStorage.getItem("dynsec.topicFilters");if(value===null)return [...DEFAULT_TOPIC_FILTERS];const filters=JSON.parse(value);return Array.isArray(filters)?filters:[...DEFAULT_TOPIC_FILTERS]}catch{return [...DEFAULT_TOPIC_FILTERS]}}
function saveTopicFilters(){localStorage.setItem("dynsec.topicFilters",JSON.stringify(topicFilters))}
function uid(){return crypto.randomUUID?crypto.randomUUID():Date.now()+"-"+Math.random().toString(16).slice(2)}
function setStatus(s,t){$("#statusDot").className="dot "+s;$("#statusText").textContent=t;$("#disconnectBtn").disabled=s!=="on"}
function setConnecting(waiting){$("#connectionWaitText").textContent=activeConn?`Connecting to ${activeConn.name}…`:"Connecting…";$("#connectionOverlay").classList.toggle("hidden",!waiting)}
function readablePayload(payload){const text=typeof payload==="string"?payload:payload.toString();try{return JSON.stringify(JSON.parse(text),null,2)}catch{return text}}
function logTraffic(direction,topic,payload,meta={}){if(mutedLogTopics.has(topic))return;trafficLog.push({id:uid(),direction,topic,payload:readablePayload(payload),qos:meta.qos??0,retain:!!meta.retain,time:new Date(),connection:activeConn?.name||""});if(trafficLog.length>500)trafficLog.shift();scheduleLogRender()}
function scheduleLogRender(){if(logRenderPending)return;logRenderPending=true;requestAnimationFrame(()=>{logRenderPending=false;renderTrafficLog()})}
function scrollLogToBottom(){const list=$("#trafficLog");if(list)list.scrollTop=list.scrollHeight}
function renderTrafficLog(){const list=$("#trafficLog");if(!list)return;const previousScroll=list.scrollTop,autoScroll=$("#logAutoScroll").checked;list.innerHTML=trafficLog.length?trafficLog.map(entry=>`<article class="log-entry"><div class="log-head"><span class="log-direction ${entry.direction}">${entry.direction==="out"?"PUBLISH":"RECEIVED"}</span><time datetime="${entry.time.toISOString()}">${esc(entry.time.toLocaleTimeString())}</time><span class="tag">QoS ${entry.qos}</span>${entry.retain?'<span class="tag">Retained</span>':""}<span class="log-topic">${esc(entry.connection?entry.connection+" · ":"")}${esc(entry.topic)}</span><div class="log-actions"><button class="ghost" data-copy-log="${entry.id}">Copy payload</button><button class="ghost" data-mute-log="${entry.id}">${mutedLogTopics.has(entry.topic)?"Unmute topic":"Mute topic"}</button></div></div><pre>${esc(entry.payload)}</pre></article>`).join(""):'<div class="panel muted">No MQTT traffic yet.</div>';$$('[data-copy-log]').forEach(button=>button.onclick=()=>copyLogPayload(button.dataset.copyLog));$$('[data-mute-log]').forEach(button=>button.onclick=()=>toggleMuteLogTopic(button.dataset.muteLog));$("#unmuteAllBtn").disabled=mutedLogTopics.size===0;$("#unmuteAllBtn").textContent=mutedLogTopics.size?`Unmute all (${mutedLogTopics.size})`:"Unmute all";autoScroll?scrollLogToBottom():list.scrollTop=previousScroll}
async function copyText(text){try{await navigator.clipboard.writeText(text);toast("Payload copied")}catch{const area=document.createElement("textarea");area.value=text;area.style.position="fixed";area.style.opacity="0";document.body.append(area);area.select();const copied=document.execCommand("copy");area.remove();toast(copied?"Payload copied":"Could not copy payload",!copied)}}
function copyLogPayload(id){const entry=trafficLog.find(item=>item.id===id);if(entry)copyText(entry.payload)}
function toggleMuteLogTopic(id){const entry=trafficLog.find(item=>item.id===id);if(!entry)return;if(mutedLogTopics.has(entry.topic)){mutedLogTopics.delete(entry.topic);toast(`Unmuted ${entry.topic}`)}else{mutedLogTopics.add(entry.topic);toast(`Muted ${entry.topic}`)}renderTrafficLog()}

function validTopicFilter(filter){if(!filter||filter.includes("\0"))return false;const levels=filter.split("/");return levels.every((level,index)=>{if(level.includes("#"))return level==="#"&&index===levels.length-1;if(level.includes("+"))return level==="+";return true})}
function validPublishTopic(topic){return !!topic&&!topic.includes("\0")&&!topic.includes("#")&&!topic.includes("+")}
function renderSubscriptions(){$("#topicSubscriptions").innerHTML=topicFilters.length?topicFilters.map(filter=>`<span class="subscription-chip">${esc(filter)}<button class="danger" data-remove-subscription="${esc(filter)}" title="Unsubscribe" aria-label="Unsubscribe from ${esc(filter)}">×</button></span>`).join(""):'<span class="muted">No topic filters. Add one below to begin browsing.</span>';$$('[data-remove-subscription]').forEach(button=>button.onclick=()=>removeTopicFilter(button.dataset.removeSubscription))}
function subscribeTopicFilter(filter,notify=false){if(!mqttClient?.connected)return;mqttClient.subscribe(filter,{qos:0},err=>{if(err){toast(`Could not subscribe to ${filter}: ${err.message}`,true);return}if(notify)toast(`Subscribed to ${filter}`)})}
function subscribeTopicFilters(){topicFilters.forEach(filter=>subscribeTopicFilter(filter))}
function addTopicFilter(){const input=$("#subscriptionFilter"),filter=input.value.trim();if(!validTopicFilter(filter)){toast("Enter a valid MQTT topic filter",true);return}if(topicFilters.includes(filter)){toast("That topic filter is already subscribed",true);return}topicFilters.push(filter);saveTopicFilters();renderSubscriptions();subscribeTopicFilter(filter,true);input.value=""}
function removeTopicFilter(filter){topicFilters=topicFilters.filter(item=>item!==filter);saveTopicFilters();renderSubscriptions();if(mqttClient?.connected)mqttClient.unsubscribe(filter,err=>toast(err?`Could not unsubscribe from ${filter}: ${err.message}`:`Unsubscribed from ${filter}`,!!err))}
function recordTopicMessage(topic,payload,packet={}){const entry={topic,payload:readablePayload(payload),qos:packet.qos??0,retain:!!packet.retain,time:new Date()};topicMessages.delete(topic);topicMessages.set(topic,entry);while(topicMessages.size>1000)topicMessages.delete(topicMessages.keys().next().value);scheduleTopicRender()}
function scheduleTopicRender(){if(topicRenderPending)return;topicRenderPending=true;requestAnimationFrame(()=>{topicRenderPending=false;renderTopicBrowser()})}
function renderTopicBrowser(){renderTopicTree();renderTopicDetail()}
function renderTopicTree(){const tree=$("#topicTree");$("#topicCount").textContent=`${topicMessages.size} discovered`;if(!topicMessages.size){tree.innerHTML='<p class="muted">Waiting for messages…</p>';return}const root={children:new Map()};[...topicMessages.values()].sort((a,b)=>a.topic.localeCompare(b.topic)).forEach(entry=>{let node=root;entry.topic.split("/").forEach(part=>{if(!node.children.has(part))node.children.set(part,{children:new Map(),entry:null});node=node.children.get(part)});node.entry=entry});const branch=node=>`<ul>${[...node.children.entries()].map(([name,child])=>`<li>${child.entry?`<button class="topic-node ${selectedTopic===child.entry.topic?"selected":""}" data-select-topic="${esc(child.entry.topic)}"><span class="topic-pulse"></span>${esc(name||"(empty)")}</button>`:`<div class="topic-node branch">${esc(name||"(empty)")}</div>`}${child.children.size?branch(child):""}</li>`).join("")}</ul>`;tree.innerHTML=branch(root);$$('[data-select-topic]').forEach(button=>button.onclick=()=>{selectedTopic=button.dataset.selectTopic;$("#publishTopic").value=selectedTopic;renderTopicBrowser()})}
function renderTopicDetail(){const detail=$("#topicDetail"),entry=topicMessages.get(selectedTopic);if(!entry){detail.innerHTML='<p class="muted">Select a discovered topic to inspect its latest message.</p>';return}detail.innerHTML=`<div class="topic-detail-head"><div><strong>Latest message</strong><div class="topic-detail-name">${esc(entry.topic)}</div></div><button id="copyTopicPayload" class="ghost">Copy payload</button></div><div class="topic-meta"><span class="tag">${esc(entry.time.toLocaleString())}</span><span class="tag">QoS ${entry.qos}</span>${entry.retain?'<span class="tag">Retained</span>':""}</div><pre>${esc(entry.payload)}</pre>`;$("#copyTopicPayload").onclick=()=>copyText(entry.payload)}

function renderConnections(){
 const list=$("#connectionList"), cs=saved();
 list.innerHTML=cs.length?cs.map(c=>`<div class="connection ${activeConn?.id===c.id?"active":""}">
 <div class="connection-title">${esc(c.name)}</div><div class="connection-url">${esc(c.url)}</div>
 <div class="connection-actions"><button data-connect="${c.id}">Connect</button><button class="ghost" data-editconn="${c.id}">Edit</button><button class="danger" data-delconn="${c.id}">Delete</button></div></div>`).join(""):'<p class="muted">No saved connections.</p>';
 $$("[data-connect]").forEach(b=>b.onclick=()=>promptConnect(b.dataset.connect));
 $$("[data-editconn]").forEach(b=>b.onclick=()=>editConnection(b.dataset.editconn));
 $$("[data-delconn]").forEach(b=>b.onclick=()=>{if(confirm("Delete this saved connection?")){saveConns(saved().filter(c=>c.id!==b.dataset.delconn));renderConnections()}});
}
function editConnection(id){
 const c=saved().find(x=>x.id===id)||{id:"",name:"",url:"wss://",username:"",password:"",clientId:"",protocolVersion:4};
 $("#connDialogTitle").textContent=id?"Edit connection":"New connection";$("#connId").value=c.id;$("#connName").value=c.name;$("#connUrl").value=c.url;$("#connUsername").value=c.username||"";$("#connPassword").value=c.password||"";$("#connClientId").value=c.clientId||"";$("#connVersion").value=String(c.protocolVersion||4);$("#connDialog").showModal();
}
$("#newConnBtn").onclick=()=>editConnection();
$("#connForm").addEventListener("submit",e=>{
 if(e.submitter?.value==="cancel")return;
 e.preventDefault();let url=$("#connUrl").value.trim();
 if(!/^wss?:\/\//i.test(url)){toast("Browser MQTT connections must use ws:// or wss://",true);return}
 let cs=saved(),id=$("#connId").value||uid(), c={id,name:$("#connName").value.trim(),url,username:$("#connUsername").value.trim(),password:$("#connPassword").value,clientId:$("#connClientId").value.trim(),protocolVersion:+$("#connVersion").value};
 let i=cs.findIndex(x=>x.id===id);if(i>=0)cs[i]=c;else cs.push(c);saveConns(cs);$("#connDialog").close();renderConnections();
});
function promptConnect(id){activeConn=saved().find(c=>c.id===id);if(!activeConn)return;if(Object.hasOwn(activeConn,"password")){connect(activeConn.password);return}$("#passwordConnectionLabel").textContent=`${activeConn.name} — ${activeConn.url}`;$("#connectPassword").value="";$("#passwordDialog").showModal();setTimeout(()=>$("#connectPassword").focus(),50)}
$("#passwordForm").addEventListener("submit",e=>{if(e.submitter?.value==="cancel")return;e.preventDefault();const password=$("#connectPassword").value;activeConn.password=password;saveConns(saved().map(c=>c.id===activeConn.id?activeConn:c));$("#passwordDialog").close();connect(password)});
function connect(password){
 const previous=mqttClient;mqttClient=null;if(previous)try{previous.end(true)}catch{}
 if(location.protocol==="https:"&&/^ws:\/\//i.test(activeConn.url)){setStatus("off","Disconnected");setConnecting(false);toast("Browsers block ws:// from HTTPS. Serve DynSecUI over http:// for this local connection, or enable wss:// on the broker.",true);return}
 topicMessages.clear();selectedTopic=null;renderTopicBrowser();
 setStatus("wait","Connecting…");setConnecting(true);
 const o={username:activeConn.username||undefined,password:password||undefined,clientId:activeConn.clientId||("dynsec-web-"+Math.random().toString(16).slice(2,10)),protocolVersion:activeConn.protocolVersion||4,clean:true,reconnectPeriod:0,connectTimeout:10000};
 let client;try{client=mqtt.connect(activeConn.url,o);mqttClient=client}catch(e){setConnecting(false);setStatus("off","Disconnected");toast(e.message,true);return}
 client.on("connect",()=>{if(mqttClient!==client)return;client.subscribe(RESPONSE,{qos:1},err=>{if(mqttClient!==client)return;if(err){setConnecting(false);setStatus("off","Disconnected");toast("Failed to subscribe to DynSec responses: "+err.message,true);mqttClient=null;client.end(true);return}setConnecting(false);setStatus("on",activeConn.name);$("#welcome").classList.add("hidden");$("#app").classList.remove("hidden");renderConnections();subscribeTopicFilters();refreshAll()})});
 client.on("message",(topic,payload,packet)=>{if(mqttClient!==client)return;recordTopicMessage(topic,payload,packet);logTraffic("in",topic,payload,{qos:packet?.qos,retain:packet?.retain});if(topic!==RESPONSE)return;let obj;try{obj=JSON.parse(payload.toString())}catch{return}handleResponse(obj)});
 client.on("error",e=>{if(mqttClient!==client)return;setConnecting(false);toast("MQTT: "+e.message,true)});
 client.on("close",()=>{if(mqttClient!==client)return;setConnecting(false);mqttClient=null;if($("#statusDot").classList.contains("on"))toast("Broker connection closed",true);setStatus("off","Disconnected")});
}
$("#disconnectBtn").onclick=()=>{const client=mqttClient;mqttClient=null;if(client)client.end(true);setConnecting(false);setStatus("off","Disconnected");renderConnections()};

function dynsec(commands,timeout=8000){
 if(!mqttClient?.connected)return Promise.reject(new Error("Not connected"));
 const token=uid(), cmds=(Array.isArray(commands)?commands:[commands]).map(c=>({...c,correlationData:token}));
 return new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>{pending=pending.filter(p=>p.token!==token);reject(new Error("Timed out waiting for Dynamic Security response"))},timeout);
   pending.push({token,resolve,reject,timer});
   const payload=JSON.stringify({commands:cmds});logTraffic("out",CONTROL,payload,{qos:1,retain:false});mqttClient.publish(CONTROL,payload,{qos:1},err=>{if(err){clearTimeout(timer);pending=pending.filter(p=>p.token!==token);reject(err)}})
 });
}
function handleResponse(obj){
 const rs=obj.responses||[]; const token=rs.find(r=>r.correlationData)?.correlationData;
 if(token){const p=pending.find(x=>x.token===token);if(p){clearTimeout(p.timer);pending=pending.filter(x=>x!==p);const errors=rs.filter(r=>r.error);errors.length?p.reject(new Error(errors.map(r=>`${r.command}: ${r.error}`).join("\n"))):p.resolve(obj);return}}
 // fallback for brokers/versions that do not echo correlationData consistently
 if(pending.length===1){const p=pending.shift();clearTimeout(p.timer);const errors=rs.filter(r=>r.error);errors.length?p.reject(new Error(errors.map(r=>`${r.command}: ${r.error}`).join("\n"))):p.resolve(obj)}
}
const firstData=(res,cmd)=>res.responses?.find(r=>r.command===cmd)?.data||{};

async function refreshAll(){try{await Promise.all([loadClients(),loadGroups(),loadRoles(),loadDefaults(),loadAnonymous()]);renderAll()}catch(e){toast(e.message,true)}}
async function loadClients(){const r=await dynsec({command:"listClients",verbose:true,count:-1,offset:0});let d=firstData(r,"listClients");state.clients=d.clients||[]}
async function loadGroups(){const r=await dynsec({command:"listGroups",verbose:true,count:-1,offset:0});let d=firstData(r,"listGroups");state.groups=d.groups||[]}
async function loadRoles(){const r=await dynsec({command:"listRoles",verbose:true,count:-1,offset:0});let d=firstData(r,"listRoles");state.roles=d.roles||[]}
async function loadDefaults(){const r=await dynsec({command:"getDefaultACLAccess"}),d=firstData(r,"getDefaultACLAccess");state.defaults=Array.isArray(d.acls)?Object.fromEntries(d.acls.map(acl=>[acl.acltype,acl.allow])):d}
async function loadAnonymous(){const r=await dynsec({command:"getAnonymousGroup"});let d=firstData(r,"getAnonymousGroup");state.anonymousGroup=d.groupname??null}
function renderAll(){renderClients();renderGroups();renderRoles();renderDefaults();renderAnonymous()}
function badges(items,key){return (items||[]).map(x=>`<span class="tag">${esc(x[key])}${x.priority!==undefined?" ("+x.priority+")":""}</span>`).join("")||'<span class="muted">None</span>'}

function renderClients(){
 $("#clientsTable").innerHTML=`<table><thead><tr><th>Username</th><th>Client ID</th><th>Status</th><th>Groups</th><th>Roles</th><th></th></tr></thead><tbody>${state.clients.map(c=>`<tr><td><strong>${esc(c.username)}</strong><br><span class="muted">${esc(c.textname||"")}</span></td><td>${esc(c.clientid||"—")}</td><td>${c.disabled?'<span class="tag">Disabled</span>':'Enabled'}</td><td>${badges(c.groups,"groupname")}</td><td>${badges(c.roles,"rolename")}</td><td class="actions"><button data-editclient="${esc(c.username)}">Edit</button><button class="danger" data-delclient="${esc(c.username)}">Delete</button></td></tr>`).join("")}</tbody></table>`;
 $$("[data-editclient]").forEach(b=>b.onclick=()=>editClient(b.dataset.editclient));$$("[data-delclient]").forEach(b=>b.onclick=()=>deleteClient(b.dataset.delclient));
}
function renderGroups(){
 $("#groupsTable").innerHTML=`<table><thead><tr><th>Group</th><th>Clients</th><th>Roles</th><th></th></tr></thead><tbody>${state.groups.map(g=>`<tr><td><strong>${esc(g.groupname)}</strong><br><span class="muted">${esc(g.textname||"")}</span></td><td>${badges(g.clients,"username")}</td><td>${badges(g.roles,"rolename")}</td><td class="actions"><button data-editgroup="${esc(g.groupname)}">Edit</button><button class="danger" data-delgroup="${esc(g.groupname)}">Delete</button></td></tr>`).join("")}</tbody></table>`;
 $$("[data-editgroup]").forEach(b=>b.onclick=()=>editGroup(b.dataset.editgroup));$$("[data-delgroup]").forEach(b=>b.onclick=()=>deleteGroup(b.dataset.delgroup));
}
function renderRoles(){
 $("#rolesTable").innerHTML=`<table><thead><tr><th>Role</th><th>ACLs</th><th></th></tr></thead><tbody>${state.roles.map(r=>`<tr><td><strong>${esc(r.rolename)}</strong><br><span class="muted">${esc(r.textname||"")}</span></td><td>${(r.acls||[]).map(a=>`<div><span class="tag">${esc(a.acltype)}</span> ${esc(a.topic)} — ${a.allow?"allow":"deny"} (${a.priority??-1})</div>`).join("")||'<span class="muted">None</span>'}</td><td class="actions"><button data-editrole="${esc(r.rolename)}">Edit</button><button class="danger" data-delrole="${esc(r.rolename)}">Delete</button></td></tr>`).join("")}</tbody></table>`;
 $$("[data-editrole]").forEach(b=>b.onclick=()=>editRole(b.dataset.editrole));$$("[data-delrole]").forEach(b=>b.onclick=()=>deleteRole(b.dataset.delrole));
}
function renderDefaults(){
 const d=state.defaults;$("#defaultAclPanel").innerHTML=["publishClientSend","publishClientReceive","subscribe","unsubscribe"].map(t=>`<div class="switchline"><strong>${t}</strong><select data-default="${t}"><option value="true" ${d[t]===true?"selected":""}>allow</option><option value="false" ${d[t]===false?"selected":""}>deny</option></select></div>`).join("")+`<div style="margin-top:14px"><button id="saveDefaultsBtn">Save defaults</button></div>`;
 $("#saveDefaultsBtn").onclick=async()=>{try{const acls=$$("[data-default]").map(s=>({acltype:s.dataset.default,allow:s.value==="true"}));await dynsec({command:"setDefaultACLAccess",acls});toast("Default ACL access updated");await loadDefaults();renderDefaults()}catch(e){toast(e.message,true)}};
}
function renderAnonymous(){
 $("#anonymousGroup").innerHTML=`<option value="">None</option>`+state.groups.map(g=>`<option value="${esc(g.groupname)}" ${state.anonymousGroup===g.groupname?"selected":""}>${esc(g.groupname)}</option>`).join("");
}
$("#saveAnonymousBtn").onclick=async()=>{try{await dynsec({command:"setAnonymousGroup",groupname:$("#anonymousGroup").value||null});toast("Anonymous group updated");await loadAnonymous();renderAnonymous()}catch(e){toast(e.message,true)}};

function optionRows(items,nameKey,selected){
 return items.map(i=>{let name=i[nameKey],x=(selected||[]).find(v=>v[nameKey]===name);return `<div class="listrow"><label><input type="checkbox" data-name="${esc(name)}" ${x?"checked":""}> ${esc(name)}</label><input type="number" data-priority="${esc(name)}" value="${x?.priority??-1}" min="-1" max="100000"><span></span></div>`}).join("");
}
async function editClient(username){
 let isNew=!username,c=isNew?{username:"",clientid:"",textname:"",textdescription:"",disabled:false,groups:[],roles:[]}:(await dynsec({command:"getClient",username})).responses.find(x=>x.command==="getClient").data.client;
 $("#editorTitle").textContent=isNew?"Create client":"Edit client: "+username;
 $("#editorBody").innerHTML=`<div class="grid2">
 <label>Username<input id="eUser" value="${esc(c.username)}" ${isNew?"":"disabled"}></label><label>Client ID<input id="eClientId" value="${esc(c.clientid||"")}"></label>
 <label>Text name<input id="eTextName" value="${esc(c.textname||"")}"></label><label>Password<input id="ePassword" type="password" placeholder="${isNew?"Optional":"Leave blank to keep current"}"></label></div>
 <label>Text description<textarea id="eDesc">${esc(c.textdescription||"")}</textarea></label>
 <label><input id="eDisabled" type="checkbox" ${c.disabled?"checked":""} style="width:auto"> Disabled</label>
 <div class="subpanel"><div class="subhead"><strong>Groups</strong><span class="muted">priority</span></div><div id="clientGroups">${optionRows(state.groups,"groupname",c.groups)}</div></div>
 <div class="subpanel"><div class="subhead"><strong>Direct roles</strong><span class="muted">priority</span></div><div id="clientRoles">${optionRows(state.roles,"rolename",c.roles)}</div></div>
 <div class="dialog-actions"><button id="saveClient">Save</button></div>`;
 $("#editorDialog").showModal();
 $("#saveClient").onclick=async e=>{e.preventDefault();let groups=[...$("#clientGroups").querySelectorAll("input[type=checkbox]:checked")].map(x=>({groupname:x.dataset.name,priority:+$("#clientGroups").querySelector(`[data-priority="${CSS.escape(x.dataset.name)}"]`).value}));let roles=[...$("#clientRoles").querySelectorAll("input[type=checkbox]:checked")].map(x=>({rolename:x.dataset.name,priority:+$("#clientRoles").querySelector(`[data-priority="${CSS.escape(x.dataset.name)}"]`).value}));let cmd={command:isNew?"createClient":"modifyClient",username:$("#eUser").value.trim(),clientid:$("#eClientId").value,textname:$("#eTextName").value,textdescription:$("#eDesc").value,groups,roles};if($("#ePassword").value)cmd.password=$("#ePassword").value;try{await dynsec(cmd);if(!isNew){await dynsec({command:$("#eDisabled").checked?"disableClient":"enableClient",username})}else if($("#eDisabled").checked){await dynsec({command:"disableClient",username:cmd.username})}toast("Client saved");$("#editorDialog").close();await loadClients();renderClients()}catch(ex){toast(ex.message,true)}}
}
async function deleteClient(u){if(!confirm(`Delete client "${u}"? Connected clients using it will be disconnected.`))return;try{await dynsec({command:"deleteClient",username:u});toast("Client deleted");await loadClients();renderClients()}catch(e){toast(e.message,true)}}

async function editGroup(name){
 let isNew=!name,g=isNew?{groupname:"",textname:"",textdescription:"",roles:[]}:(await dynsec({command:"getGroup",groupname:name})).responses.find(x=>x.command==="getGroup").data.group;
 $("#editorTitle").textContent=isNew?"Create group":"Edit group: "+name;
 $("#editorBody").innerHTML=`<div class="grid2"><label>Group name<input id="eGroup" value="${esc(g.groupname)}" ${isNew?"":"disabled"}></label><label>Text name<input id="eTextName" value="${esc(g.textname||"")}"></label></div><label>Text description<textarea id="eDesc">${esc(g.textdescription||"")}</textarea></label><div class="subpanel"><div class="subhead"><strong>Roles</strong><span class="muted">priority</span></div><div id="groupRoles">${optionRows(state.roles,"rolename",g.roles)}</div></div><div class="dialog-actions"><button id="saveGroup">Save</button></div>`;
 $("#editorDialog").showModal();$("#saveGroup").onclick=async e=>{e.preventDefault();let roles=[...$("#groupRoles").querySelectorAll("input[type=checkbox]:checked")].map(x=>({rolename:x.dataset.name,priority:+$("#groupRoles").querySelector(`[data-priority="${CSS.escape(x.dataset.name)}"]`).value}));let cmd={command:isNew?"createGroup":"modifyGroup",groupname:$("#eGroup").value.trim(),textname:$("#eTextName").value,textdescription:$("#eDesc").value,roles};try{await dynsec(cmd);toast("Group saved");$("#editorDialog").close();await Promise.all([loadGroups(),loadClients()]);renderGroups();renderClients()}catch(ex){toast(ex.message,true)}}
}
async function deleteGroup(g){if(!confirm(`Delete group "${g}"?`))return;try{await dynsec({command:"deleteGroup",groupname:g});toast("Group deleted");await Promise.all([loadGroups(),loadClients()]);renderAll()}catch(e){toast(e.message,true)}}

function aclRows(acls){
 return (acls||[]).map((a,i)=>`<div class="aclrow" data-aclrow><select data-acltype>${ACL_TYPES.map(t=>`<option ${t===a.acltype?"selected":""}>${t}</option>`).join("")}</select><input data-topic value="${esc(a.topic)}" placeholder="topic/#"><select data-allow><option value="true" ${a.allow?"selected":""}>allow</option><option value="false" ${!a.allow?"selected":""}>deny</option></select><input type="number" data-apriority value="${a.priority??-1}" min="-1" max="100000"><button class="danger" data-rmacl>×</button></div>`).join("");
}
async function editRole(name){
 let isNew=!name,r=isNew?{rolename:"",textname:"",textdescription:"",acls:[]}:(await dynsec({command:"getRole",rolename:name})).responses.find(x=>x.command==="getRole").data.role;
 $("#editorTitle").textContent=isNew?"Create role":"Edit role: "+name;
 $("#editorBody").innerHTML=`<div class="grid2"><label>Role name<input id="eRole" value="${esc(r.rolename)}" ${isNew?"":"disabled"}></label><label>Text name<input id="eTextName" value="${esc(r.textname||"")}"></label></div><label>Text description<textarea id="eDesc">${esc(r.textdescription||"")}</textarea></label><div class="subpanel"><div class="subhead"><strong>ACLs</strong><button id="addAcl" class="ghost">+ ACL</button></div><div id="aclRows">${aclRows(r.acls)}</div></div><div class="dialog-actions"><button id="saveRole">Save</button></div>`;
 $("#editorDialog").showModal();bindAclRemove();$("#addAcl").onclick=e=>{e.preventDefault();$("#aclRows").insertAdjacentHTML("beforeend",aclRows([{acltype:"publishClientSend",topic:"#",allow:true,priority:-1}]));bindAclRemove()};
 $("#saveRole").onclick=async e=>{e.preventDefault();let acls=$$("#aclRows [data-aclrow]").map(row=>({acltype:row.querySelector("[data-acltype]").value,topic:row.querySelector("[data-topic]").value,allow:row.querySelector("[data-allow]").value==="true",priority:+row.querySelector("[data-apriority]").value}));let cmd={command:isNew?"createRole":"modifyRole",rolename:$("#eRole").value.trim(),textname:$("#eTextName").value,textdescription:$("#eDesc").value,acls};try{await dynsec(cmd);toast("Role saved");$("#editorDialog").close();await Promise.all([loadRoles(),loadClients(),loadGroups()]);renderAll()}catch(ex){toast(ex.message,true)}}
}
function bindAclRemove(){$$("[data-rmacl]").forEach(b=>b.onclick=e=>{e.preventDefault();b.closest("[data-aclrow]").remove()})}
async function deleteRole(r){if(!confirm(`Delete role "${r}"?`))return;try{await dynsec({command:"deleteRole",rolename:r});toast("Role deleted");await Promise.all([loadRoles(),loadClients(),loadGroups()]);renderAll()}catch(e){toast(e.message,true)}}

$("#addClientBtn").onclick=()=>editClient();$("#addGroupBtn").onclick=()=>editGroup();$("#addRoleBtn").onclick=()=>editRole();
$$("[data-refresh]").forEach(b=>b.onclick=async()=>{try{let x=b.dataset.refresh;if(x==="clients")await loadClients();if(x==="groups")await loadGroups();if(x==="roles")await loadRoles();if(x==="defaults"){await Promise.all([loadDefaults(),loadAnonymous()])}renderAll();toast("Refreshed")}catch(e){toast(e.message,true)}});

$$(".tabs button").forEach(b=>b.onclick=()=>{$$(".tabs button").forEach(x=>x.classList.toggle("active",x===b));$$(".tab").forEach(t=>t.classList.toggle("active",t.id===b.dataset.tab));if(b.dataset.tab==="log"&&$("#logAutoScroll").checked)requestAnimationFrame(scrollLogToBottom)});
$("#formatRawBtn").onclick=()=>{try{$("#rawCommand").value=JSON.stringify(JSON.parse($("#rawCommand").value),null,2)}catch(e){toast("Invalid JSON: "+e.message,true)}};
$("#sendRawBtn").onclick=async()=>{try{let obj=JSON.parse($("#rawCommand").value);if(!obj.commands||!Array.isArray(obj.commands))throw new Error('Top-level object must contain a "commands" array');let r=await dynsec(obj.commands);$("#rawResponse").textContent=JSON.stringify(r,null,2)}catch(e){$("#rawResponse").textContent=e.message;toast(e.message,true)}};
$("#clearLogBtn").onclick=()=>{trafficLog=[];renderTrafficLog()};
$("#logAutoScroll").onchange=()=>{if($("#logAutoScroll").checked)scrollLogToBottom()};
$("#unmuteAllBtn").onclick=()=>{mutedLogTopics.clear();renderTrafficLog();toast("All log topics unmuted")};
$("#addSubscriptionBtn").onclick=addTopicFilter;
$("#subscriptionFilter").addEventListener("keydown",event=>{if(event.key==="Enter"){event.preventDefault();addTopicFilter()}});
$("#clearTopicsBtn").onclick=()=>{topicMessages.clear();selectedTopic=null;renderTopicBrowser()};
$("#publishTopicBtn").onclick=()=>{if(!mqttClient?.connected){toast("Not connected",true);return}const topic=$("#publishTopic").value.trim(),payload=$("#publishPayload").value,qos=+$("#publishQos").value,retain=$("#publishRetain").checked;if(!validPublishTopic(topic)){toast("Enter a valid publish topic without wildcards",true);return}logTraffic("out",topic,payload,{qos,retain});mqttClient.publish(topic,payload,{qos,retain},err=>toast(err?"Publish failed: "+err.message:"Message published",!!err))};

$("#appVersion").textContent=`DynSecUI v${APP_VERSION}`;renderConnections();renderSubscriptions();renderTopicBrowser();setStatus("off","Disconnected");
})();
