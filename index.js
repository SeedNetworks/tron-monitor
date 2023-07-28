const fs                = require('fs');
const WebSocket         = require('ws');
const https             = require("https");
const chokidar          = require('chokidar');
const Crypto            = require('./crypto');
const {ProxyAgent}      = require('proxy-agent');

var config;
var addresses = [];
var Contracts = {};
var Tokens    = {};
var txslog    = process.cwd()+"/txs.log";
var last      = 0;

function getProxy(){
  return new ProxyAgent('socks5://'+config.proxy.user+':'+config.proxy.pass+'@'+config.proxy.host+':'+config.proxy.port);
}
function blockScan(method, post, proxy){
  return new Promise(async (resolve,reject) => {
      const req = https.request({
        hostname: (method.indexOf('notify') >= 0) ? config.notify.host : 'api.trongrid.io',
        agent: proxy == true ? getProxy() : false,
        port: (method.indexOf('notify') >= 0) ? config.notify.port : 443,
        path: (method.indexOf('notify') >= 0) ? '/'+config.notify.path : '/'+method,
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'Content-Length': JSON.stringify(post).length}
      }, res => {
        res.setEncoding('utf8');
        const chunks = [];
        res.on('data', data => chunks.push(data))
        res.on('end', () => resolve(JSON.parse(chunks.join(''))))
    })
    req.on('error',reject);
    if(post) req.write(JSON.stringify(post));
    req.end();
  })
}
function contractsLoad(){
  if(!fs.existsSync('tokens.json')){
    var tokens = [];
    async function getTokens(offset = 0, limit = 200){
      var result = await blockScan('wallet/getpaginatedassetissuelist', {offset: offset, limit: limit}, true)
      if(result.assetIssue && result.assetIssue.length > 0){
        result.assetIssue.map(token => {
            var tok = {
              ...token,
              owner_address: Crypto.addressFromHex(token.owner_address),
              decimal: token.precision,
              type: 'TRC10',
              name: toUtf8(token.name),
              chain: token.abbr && toUtf8(token.abbr),
              desc: token.description && toUtf8(token.description),
              url: token.url && toUtf8(token.url),
              id: parseInt(token.id)
          }
          delete(tok.precision)
          delete(tok.abbr)
          delete(tok.description)
          tokens.push(tok)
        })
        await getTokens(offset+limit, limit)
      }
      else return tokens
    }
    getTokens().then(() => {
      fs.writeFileSync(process.cwd()+'/tokens.json', JSON.stringify(tokens, null, 4))
      fileLoad('tokens.json').map((t) => {Tokens[t.id] = t});
    })
  }
  else fileLoad('tokens.json').map((t) => {Tokens[t.id] = t})
  fs.readdirSync(process.cwd()+"/contracts").map((c) => {
    Contracts[c.split('.')[0]] = fileLoad('contracts/'+c);
  })
}
function fileLoad(filename){
  var raw = fs.readFileSync(process.cwd()+"/"+filename, {encoding: "utf8"});
  return (filename.indexOf("json") > 2) ? JSON.parse(raw) : raw
}
function resetConfig(){
  config  = fileLoad("config.json");
  console.log("Конфиг загружен");
}
function resetAddresses(){
  addresses = fileLoad("addresses.conf").split("\n");
  console.log((addresses.length-1)+" Адресов загружено");
}
chokidar.watch('.', {awaitWriteFinish: true, alwaysStat: true, ignored: 'node_modules'})
.on('all', async(event, path) => {
  if(event == "change" && path == "addresses.conf") resetAddresses()
  if(event == "change" && path == "config.json") resetConfig()
  if(event == "change" && path == "contracts") contractsLoad()
})
function filterAddresses(trans){
  console.log(trans);
  if(trans.to && addresses.indexOf(trans.to) >= 0){
    console.log("New TXID: "+trans.txid);
    fs.appendFileSync(txslog, "receive - block:"+trans.block+'|txid:'+trans.txid+'|time:'+trans.time+'|address:'+trans.to+'|amount:'+trans.amount+'|chain:'+trans.chain+'\n');
    if(!config.notify) console.log("Отсутствует url для уведомлений - параметр notify в config.json")
    else blockScan('/notify', trans).then(() => console.log('Уведомление успешно отправлено'))
  }
}
async function getContract(contractAddress){
  var result = await blockScan('wallet/getcontract', {value: contractAddress, visible:true}, true)
  return result
  //if(result) fs.writeFileSync(process.cwd()+'/tokens.json', JSON.stringify(tokens, null, 4))
}
var contractDownload = false;
async function decodeTX(blockId){
  var res = await blockScan('wallet/getblockbynum', {"num": blockId, "detail": true}, true)
  console.log("Block: "+res.block_header.raw_data.number+" - "+res.blockID)
  res.transactions.map((t) => {
    t.raw_data.contract.map(async (i) => {
      var d     = i.parameter.value;
      var trans = {
        type: i.type,
        block: blockId,
        txid: t.txID,
        time: t.raw_data.timestamp,
        hex: t.raw_data_hex,
        sig: t.signature,
        from: Crypto.addressFromHex(d.owner_address)
      }
      if(d.contract_address){
        if(contractDownload == true && !Contracts[d.contract_address]) await getContract(Crypto.addressFromHex(d.contract_address))
        if(Contracts[d.contract_address]){
          var methodName = d.data.substring(0, 8);
          var inputData  = d.data.substring(8);
          trans.chain    = Contracts[d.contract_address].chain
          var length     = 64
          for(let p in Contracts[d.contract_address].abi){
            var a = Contracts[d.contract_address].abi[p]
            if(a.sig == methodName){
              trans.method = a.name
              var cursor   = 0
              a.inputs.forEach(k => {
                trans[k.name.replace('_', "")] = inputData.substring(cursor, length);
                if(k.name.replace('_', "") == 'to') trans.to = Crypto.addressFromHex('41'+trans.to.substr(trans.to.length-40, trans.to.length))
                cursor = cursor+length
              })
            }
          }
          if(trans.method == 'transferFrom'){
            var from   = trans.from.substr(trans.from.length-40, trans.from.length);
            var to     = trans.hex.split(from)[1].substr(64);
            trans.from = Crypto.addressFromHex('41'+from)
            trans.to   = Crypto.addressFromHex('41'+to.substr(to.length-40, to.length))
          }
          trans.amount = parseFloat(Crypto.hexToDec(inputData.substring(inputData.length-length, inputData.length)))  * 10 ** - 6
          delete(trans.value)
        }
      }
      else{
        if(d.asset_name && Tokens[Crypto.toUtf8(d.asset_name)]){
          let thisAsset = Tokens[Crypto.toUtf8(d.asset_name)];
          trans.chain  = thisAsset.chain ? thisAsset.chain : thisAsset.name;
          trans.amount = d.amount  * 10 ** - thisAsset.decimal ? thisAsset.decimal : 6;
        }
        else{
          trans.chain  = "TRX"
          trans.amount = d.amount ? d.amount  * 10 ** - 6 : 0;
        }
      }
      if(d.to_address) trans.to  = Crypto.addressFromHex(d.to_address)
      if(trans.chain) filterAddresses(trans)
    })
  })
}
function Socket(url){
  var socket = new WebSocket(url, {agent: getProxy()});
  socket.onopen = function(event){
     console.log("Tronscanapi wss connected..")
  }
  socket.onmessage = async (evt) => {
    var tx      = JSON.parse(evt.data);
    if(tx.block_number){
      if(last != 0 && last++ != tx.block_number) decodeTX(tx.block_number--)
      else{
        decodeTX(tx.block_number)
        last = tx.block_number;
      }
    }
  }
  socket.onclose = function(){
    console.log("Connection is closed... // Restart...");
    new Socket(url);
  }
}
function start(){
  resetConfig()
  resetAddresses()
  contractsLoad()
  new Socket('wss://apilist.tronscanapi.com/api/tronsocket')
}

start()
