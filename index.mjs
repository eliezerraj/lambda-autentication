// npm install jsonwebtoken
// npm install npm install @aws-crypto/client-node
// zip -r ../lambda-autentication .

import {
    KmsKeyringNode,
    buildClient,
    CommitmentPolicy,
} from '@aws-crypto/client-node';

import jwt from 'jsonwebtoken';

const jwtKey = "my_secret_key";

const jwtExpirySeconds = 300;
var statusCode = 200;

var msg = {"message": "Succesfull"};

const headers = { 
  "Content-Type": "application/json", 
  "Access-Control-Allow-Origin" : "*" 
};

var encrypt_token;
const { encrypt, decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)
const generatorKeyId ='arn:aws:kms:us-east-2:884069944685:alias/kms-jwt'
const keyIds = [
    'arn:aws:kms:us-east-2:884069944685:key/0401e5b0-0fd0-4f68-b89d-7ed0a4b73418',
  ];
const keyring = new KmsKeyringNode({ generatorKeyId, keyIds });
const context = {
    stage: 'qa',
    purpose: 'my app autentication',
    origin: 'us-east-2',
};

var scope;
var token;

// -------------------------------    
const db_users = {
  user1: "password1",
  user2: "password2",
};
// -------------------------------    

export const handler = async(event) => {
  console.log('*** Loading lambda autentication Version 1');
  console.log("***********************");
  console.log(event);
  console.log("***********************");

  const { user, password } = event.body;

  console.log("user  : ", user );
  console.log("password  : ", password );
  console.log("db_users[user]  : ", db_users[user] );

  if (!user || !password || db_users[user] !== password) {
    statusCode = 401;
    msg.message = "User or Password Inválido";
  } else {
    scope = {
      scope: [ "openid", "profile", "email", "offline_access" ],
    };
  
    token =  jwt.sign({ user , scope},
                              jwtKey, {
                                  algorithm: "HS256",
                                  expiresIn: jwtExpirySeconds,
                              });
          
    console.log("-----------------------------------------");
    console.log("token:", token);
  
    encrypt_token = await encrypt(keyring, token, { encryptionContext: context });
    //console.log("-----------------------------------------");
    //console.log("encrypt_token:", encrypt_token);
    //console.log("-----------------------------------------");
    //console.log("encrypt_token.result:", encrypt_token.result.toString('base64'));
    //console.log("-----------------------------------------");
  }

  const response = {
    statusCode: statusCode,
    headers: headers,
    token: token,
    encrypt_token: encrypt_token.result.toString('base64'),
    body: msg,
  };

  return response;
};
