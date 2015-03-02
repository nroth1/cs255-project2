var fs = require('fs');
var http = require('http');
var lib = require('./lib');
var querystring = require('querystring');
var sjcl = require('./sjcl');

// Parameters for the registration script
// TODO: fill in these parameters
var params = {
  'suid': 'nroth',
  'token': 'fb3c9c5013d66eb29b49ac1391b40fc604d2708b7f7c351c7ab0ddd30fc9c430',
  'password': 'a45basdp03m04n6cdxza120x'
}

// Signs the token using the ECDSA signing key and returns the signature
//   signing_key: a ECDSA signing key
//   token:       hex-encoded token from the course staff
//   
//   Returns: hex encoded signature on token
function sign_token(signing_key, token) {
  // TODO: Compute the signature
  var bit_token = lib.hex_to_bitarray(token);
  return lib.bitarray_to_hex(lib.ECDSA_sign(signing_key,bit_token));
  //return lib.bitarray_to_hex(lib.random_bitarray(128));
}

/*******************************************************************************
 * WARNING - YOU SHOULD NOT NEED TO EDIT BELOW THIS LINE                       *
 *******************************************************************************/

function read_file(f) {
  return fs.read_fileSync(f).toString('utf8').trim();
}

function register() {
  console.log('Generating ECDSA keys...');

  var token = params.token;
  var key = lib.ECDSA_key_gen(params.password);
  var signing_key = lib.ECDSA_load_sec_key(key.sec, params.password);
  var signature = sign_token(signing_key, token);

  // Write signature keys to disk
  if (!fs.existsSync('data')) {
    fs.mkdirSync('data');
  }
  fs.writeFileSync('data/key.pub', key.pub);
  fs.writeFileSync('data/key.sec', key.sec);

  // Prepare POST request to server
  var post_data = querystring.stringify({
    'suid' : params.suid,
    'pub_key': key.pub,
    'signature': signature
  });

  var post_options = {
    host: 'ec2-54-67-122-91.us-west-1.compute.amazonaws.com',
    port: '8900',
    method: 'POST'
  };

  console.log('Connecting to registration server...');

  var post_req = http.request(post_options, function (res) {
    res.setEncoding('utf8');
    
    var response_data = '';
    res.on('data', function (chunk) {
      response_data += chunk;
    });

    res.on('end', function (chunk) {
      if (response_data == "SUCCESS") {
        console.log('Registration successful.');
      } else {
        console.log('Registration failed.');
      }
    });
  });

  post_req.write(post_data);
  post_req.end();
}

register();
