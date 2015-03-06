var client = require('./client');
var lib = require('./lib');

var fs = require('fs');

var client_pw = 'password for your client key';
var suid = 'your sunet username'

var ca_crt = fs.readFileSync('data/cs255ca.pem');
var client_sec_key = fs.readFileSync('data/key.sec').toString('utf8');

var host = 'ec2-54-67-122-91.us-west-1.compute.amazonaws.com';
var port = Math.floor(Math.random() * 50) + 8800;
var client1 = client.client(client_sec_key, client_pw, ca_crt, suid);

console.log('making a connection to ' + host + ' on port ' + port);
client1.connect(host, port);
