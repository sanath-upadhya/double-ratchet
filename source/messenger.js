"use strict";
/**
 * The final takehome coding assignment was done by 
 * Stelios and Sanath
 */
/********* Imports ********/
import { subtle } from "crypto";
import {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  //printCryptoKey, // async
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
} from "./lib.js";

import { govEncryptionDataStr } from "./lib.js";

/********* Implementation ********/

export default class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey;
    this.govPublicKey = govPublicKey;
    this.conns = {}; // data for each active connection
    this.certs = {}; // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

/**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
 async generateCertificate(username) {
  this.EGKeyPair = await generateEG();
  // Certificate structure is username and public key
  const certificate = {
	'username': username,
	'pub': this.EGKeyPair.pub
  };
  return certificate;
}

/**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
async receiveCertificate(certificate, signature) {
  // If signature is not valid, throw an exception
  if ( ! await verifyWithECDSA( this.caPublicKey, JSON.stringify( certificate ), signature ) ) {
		throw("invalid certificate signature!");
	}

	this.certs[ certificate.username ] = certificate;
}

/**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
async sendMessage(name, plaintext) {

  const header = {};
  // generate new EG pair to use in this connection
	const newEGKeyPair = await generateEG();

  // check if there is any connection state
  // if not we need to generate intial root keys and initialize all the variables in conns[] 
  if ( ! ( name in this.conns ) ) {
    // generate salt key for 
    const salt = await subtle.importKey("raw", genRandomSalt( 32 ), { name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
	  // generate sending rootkey  
	  const keys = await HKDF( await computeDH( newEGKeyPair.sec, this.certs[ name ].pub ) , salt, "SendingKey" )

	  this.conns[ name ] = {};
	  //My DH key pair
    this.conns[ name ][ 'DH_PAIR_MY_PUBLIC' ] = newEGKeyPair.pub;
    this.conns[ name ][ 'DH_PAIR_MY_PRIVATE' ] = newEGKeyPair.sec;
    //The receiver's public key
	  this.conns[ name ][ 'THEIR_PUB_KEY' ] = this.certs[ name ].pub;  
    //Current root key
	  this.conns[ name ][ 'ROOT_KEY' ] = keys[ 0 ];
    //Current sending chain key
	  this.conns[ name ][ 'SENDING_CK' ] = keys[ 1 ];  
    //COunter to keep track of the number of messages sent
	  this.conns[ name ][ 'MESSAGES_SENT' ] = 0;
    //Counter to keep track of the number of messages received
    this.conns[ name ][ 'MESSAGES_RECEIVED' ] = 0;
    //Saving all rkeys needed for out-of-order messages
    this.conns[name]['SAVED_KEYS'] = [];
    //The last message number that this entity received
    this.conns[ name ][ 'LAST_MESSAGES_RECEIVED' ] = 0;
    //The total number of messages sent in the previous DH secret key
	  this.conns[ name ][ 'PREVIOUS_SENT_NUMBER' ]  = 0;
    //The salt key which acts as the root key for DH key chain
    header['SALT_KEY'] = salt;

    //If the messages received is greater than 0, that means this entity has received 
    //a new public key. Thus, if it wants to send a message back to user 'name'
    //it again needs to generate the DH key pair, with the public key present in 
    //the previous received message
  } else if (this.conns[ name ][ 'MESSAGES_RECEIVED' ] > 0) {
    const oldPublicKey = this.conns[name]['THEIR_PUB_KEY'];
    //We compute a new DH pair with the user's secret key and user 'name' public key 
    //present in the last previous message received
    const keys = await HKDF( await computeDH( newEGKeyPair.sec, this.conns[name]['THEIR_PUB_KEY'] ) ,this.conns[ name ][ 'ROOT_KEY' ], "SendingKey" );
    this.conns[ name ][ 'DH_PAIR_MY_PUBLIC' ] = newEGKeyPair.pub;
    this.conns[ name ][ 'DH_PAIR_MY_PRIVATE' ] = newEGKeyPair.sec;    
    this.conns[ name ][ 'THEIR_PUB_KEY' ] = oldPublicKey;  
    this.conns[ name ][ 'ROOT_KEY' ] = keys[ 0 ];
    this.conns[ name ][ 'SENDING_CK' ] = keys[ 1 ]; 
    this.conns[ name ][ 'PREVIOUS_SENT_NUMBER' ] =  this.conns[ name ][ 'MESSAGES_SENT' ];
    this.conns[ name ][ 'MESSAGES_SENT' ] = 0;
    this.conns[ name ][ 'MESSAGES_RECEIVED' ] = 0;
  } 

  
  // generate iv for government encryption
  header[ 'ivGov' ] = genRandomSalt( 16 );

 // generate symmetric key for government
  let govKey = await computeDH( this.EGKeyPair.sec, this.govPublicKey );
  govKey = await HMACtoAESKey(govKey, govEncryptionDataStr);
  header[ 'vGov' ] = this.EGKeyPair.pub;
  // generating gov cipher text	
  header[ 'cGov' ] = await encryptWithGCM( govKey,  await HMACtoAESKey( this.conns[ name ][ 'SENDING_CK' ], 'AES_KEY', true ), header[ 'ivGov' ] );

  //Generate new chain key for the sending chain
  const newSendingChainKey = await HMACtoHMACKey(this.conns[ name ][ 'SENDING_CK' ], 'SENDING_ROOT_KEY' );
  //Generate new message key for encoding the plaintext message
  const newMessageKey = await HMACtoAESKey(this.conns[ name ][ 'SENDING_CK' ], 'AES_KEY');
  //Update the sending key chain
  this.conns[ name ][ 'SENDING_CK' ] = newSendingChainKey;

  // encrypt message
  header[ 'receiver_iv' ] = genRandomSalt( 16 );
  this.conns[ name ][ 'MESSAGES_SENT' ] = this.conns[ name ][ 'MESSAGES_SENT' ] + 1
  header[ 'MESSAGE_NUM' ] = this.conns[ name ][ 'MESSAGES_SENT' ];
  //Send the public key of the generated DH key pair in the message header
  header[ 'PUBLIC_KEY' ] = this.conns[ name ][ 'DH_PAIR_MY_PUBLIC' ];
  header['PREVIOUS_SENT_NUMBER'] = this.conns[ name ][ 'PREVIOUS_SENT_NUMBER' ];
  const ciphertext = await encryptWithGCM( newMessageKey, plaintext, header[ 'receiver_iv' ], JSON.stringify(header));
  
  return [header, ciphertext];

}


/**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
async receiveMessage(name, [header, ciphertext]) {
  
  /**
   * We need to first intialize the conns state if the receiving entity 
   * does not have the user 'name' in it's connection state
   */
  if (! (name in this.conns)) {
    //Calculate the DH output by using the user's secret key and 
    // The received message header's public key
    const dhKeys = await computeDH(this.EGKeyPair.sec, header['PUBLIC_KEY']);
    // Perform the KDF operation on the DH output calculated
    const keys = await HKDF( dhKeys , header['SALT_KEY'], "SendingKey" );
    //Initialize all the conns variable
    this.conns[ name ] = {};
    //The 'THEIR_PUBLIC_KEY' is the public key present in the message header
    // Will be used to decide whether a double ratchet is performed on the
    //sendMessage or not
    this.conns[ name ][ 'THEIR_PUB_KEY' ] = header['PUBLIC_KEY'];
    //My DH key pair
    this.conns[ name ][ 'DH_PAIR_MY_PUBLIC' ] = this.EGKeyPair.pub;
    this.conns[ name ][ 'DH_PAIR_MY_PRIVATE' ] = this.EGKeyPair.sec;   
    //The root key for the DH key chain 
    this.conns[ name ][ 'ROOT_KEY' ] = keys[ 0 ];
    //The root key for the receiving key chain
    this.conns[ name ][ 'RECEIVING_CK' ] = keys[ 1 ]; 
    //Counters to keep track of all the messages received
    this.conns[ name ][ 'LAST_MESSAGES_RECEIVED' ] = 0;
    this.conns[ name ][ 'MESSAGES_RECEIVED' ] = 0;
    this.conns[ name ][ 'MESSAGES_SENT' ] = 0;
	  this.conns[name]['SAVED_KEYS'] = [];
    // If the public key of the message header does not match the public
    //key present in the conns state, then a DH ratchet has been performed
    //We need to only do the DH ratchet. But before that, we save the current
    //public key and the receiving key chain so that we can generate the message
    //keys needed for out-of-order messages
  } else if ( header['PUBLIC_KEY'] != this.conns[ name ][ 'THEIR_PUB_KEY' ]) {

    //In this check, we see whether the message that has arrived is a new message
    // or an out-of-order message. If it is an out-of-order message, we find the public key
    //present in th emessage header in the SAVED_KEYS
    let found_pk = false;
    for (let i=0; i<this.conns[name]['SAVED_KEYS'].length; i++) {
      if (header['PUBLIC_KEY']== this.conns[name]['SAVED_KEYS'][i].pub) {
        found_pk = true;
        break;
      }
    }

    // If the message header public key is not found in the SAVED_KEYS, we need to
    //generate all the keys needed for decoding the out-of-order messages
    //The total number of out-of-order messages sent in the previous stream can be detremined
    //by the variable 'LAST_MESSAGES_RECEIVED' present in conns[name] and the 'PREVIOUS_SENT_NUMBER'
    //present in message header
	  if ( ! found_pk ) {
		  let pubold = this.conns[ name ][ 'THEIR_PUB_KEY' ];
  		 
      //Generate all the receiving message key chain needed for out-of-order messages
		  for ( let i = this.conns[ name ][ 'LAST_MESSAGES_RECEIVED' ] + 1; i <= header[ 'PREVIOUS_SENT_NUMBER' ]; i++ ) {
			  const newReceingChainKey = await HMACtoHMACKey( this.conns[ name ][ 'RECEIVING_CK' ], 'SENDING_ROOT_KEY' );
    		const decKey = await HMACtoAESKey( this.conns[ name ][ 'RECEIVING_CK' ], 'AES_KEY');
    		this.conns[ name ][ 'RECEIVING_CK' ]  = newReceingChainKey;
        this.conns[name]['SAVED_KEYS'].push({'pub_key':pubold, 'message_num':i, 'decKey':decKey});
		  }
    	
      //Perform the DH ratchet to mimic the DH ratchet that the sender would have performed 
      //while sending the message
		  this.conns[ name ][ 'THEIR_PUB_KEY' ] = header['PUBLIC_KEY'];
    	const dhKeys = await computeDH(this.conns[name]['DH_PAIR_MY_PRIVATE'], header['PUBLIC_KEY']);
    	const keys = await HKDF( dhKeys ,this.conns[ name ][ 'ROOT_KEY' ], "SendingKey" );
    	this.conns[ name ][ 'ROOT_KEY' ] = keys[ 0 ];
    	this.conns[ name ][ 'RECEIVING_CK' ] = keys[ 1 ]; 
    	this.conns[ name ][ 'LAST_MESSAGES_RECEIVED' ] = 0;
    	this.conns[ name ][ 'MESSAGES_RECEIVED' ] = 0;
    } 

    //This is the case when the messages arrive out-of-order but are all part of the same
    //stream. That is, the sender has not performed the DH ratchet but has done the sending
    //ratchet
  } else { 
  	for (let i = this.conns[name]['LAST_MESSAGES_RECEIVED'] + 1; i<header['MESSAGE_NUM'];i++) {
    	const newReceingChainKey = await HMACtoHMACKey( this.conns[ name ][ 'RECEIVING_CK' ], 'SENDING_ROOT_KEY' );
    	const decKey = await HMACtoAESKey( this.conns[ name ][ 'RECEIVING_CK' ], 'AES_KEY');
      this.conns[name]['SAVED_KEYS'].push({'pub_key':header['PUBLIC_KEY'], 'message_num':i, 'decKey':decKey});
    	this.conns[ name ][ 'RECEIVING_CK' ]  = newReceingChainKey;
  	} 
  }

  //Variables to help in getting the decrypting chain key
  let message_num =header['MESSAGE_NUM'];
  let decKey;
  let found_in_save = false;
  let element;

  // Find the appropriate receiving chain key from the 
  //stored SHARED_KEYS. If found, delete the entry from
  //SHARED_KEYS as this is no longer needed
  for (let i =0; i<this.conns[name]['SAVED_KEYS'].length;i++) {
    if (this.conns[name]['SAVED_KEYS'][i].pub_key == header['PUBLIC_KEY'] && this.conns[name]['SAVED_KEYS'][i].message_num == message_num) {
      decKey = this.conns[name]['SAVED_KEYS'][i].decKey;
      found_in_save = true;
      element = this.conns[name]['SAVED_KEYS'].splice(i,1);
      break;
    }
  }

  //If the decKey was found, use that for performing
  //decryption. Otherwise, the key was not found in
  //the SHARED_KEYS, thus, we need to compute the decryption key
  //as the message received is in-order
  if (found_in_save) {
    //Do nothing other than delete
    //delete this.conns[name]['SAVED_KEYS'][ pubHeaderRaw ][i];
  } else {
    //Generate receiving chain key and equivalent message key 
    const newReceingChainKey = await HMACtoHMACKey( this.conns[ name ][ 'RECEIVING_CK' ], 'SENDING_ROOT_KEY' );
    decKey = await HMACtoAESKey( this.conns[ name ][ 'RECEIVING_CK' ], 'AES_KEY');
    this.conns[ name ][ 'RECEIVING_CK' ] = newReceingChainKey;
    this.conns[ name ][ 'LAST_MESSAGES_RECEIVED' ] = header['MESSAGE_NUM'];
  }

  //Decryption algorithm
  const plaintextByteArray = await decryptWithGCM(decKey, ciphertext, header['receiver_iv'], JSON.stringify(header));
  
  //Convert the byte arry to string and return the plaintext
  const plaintext = byteArrayToString(plaintextByteArray);
  this.conns[name]['MESSAGES_RECEIVED']++;
  return plaintext;
}
};
