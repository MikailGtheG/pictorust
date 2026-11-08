// Test-only TLS termination, preserving origin while proxying HTTP/WS to the
// loopback Rust server. This is NOT a production reverse proxy (use Caddy).
import https from "node:https";
import http from "node:http";
import net from "node:net";
import {readFileSync} from "node:fs";
const key=readFileSync(process.env.PICTORUST_TEST_TLS_KEY);
const cert=readFileSync(process.env.PICTORUST_TEST_TLS_CERT);
const upstream={host:"127.0.0.1",port:8787};
const proxy=https.createServer({key,cert},(req,res)=>{
 const headers={...req.headers,host:"localhost:9443"};
 delete headers["x-forwarded-proto"];
 delete headers["x-forwarded-host"];
 const client=http.request({...upstream,path:req.url,method:req.method,headers},reply=>{
   res.writeHead(reply.statusCode,reply.headers);
   reply.pipe(res);
 });
 client.on("error",()=>{if(!res.headersSent)res.writeHead(502);res.end();});
 req.pipe(client);
});
proxy.on("upgrade",(request,client,head)=>{
 const server=net.connect(upstream.port,upstream.host);
 const abort=()=>{server.destroy();client.destroy();};
 client.on("error",abort);server.on("error",abort);
 server.once("connect",()=>{
   const raw=[`${request.method} ${request.url} HTTP/1.1`];
   for(const [key,value] of Object.entries(request.headers)){
     if(key==="x-forwarded-host"||key==="x-forwarded-proto")continue;
     raw.push(`${key}: ${key==="host"?"localhost:9443":value}`);
   }
   server.write(raw.join("\r\n")+"\r\n\r\n");
   if(head.length)server.write(head);
   client.pipe(server);server.pipe(client);
 });
});
proxy.listen(9443,"127.0.0.1",()=>console.log("TLS test proxy ready on https://localhost:9443"));
