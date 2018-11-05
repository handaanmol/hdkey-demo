var HDKey = require('hdkey');
var fs = require('fs');
//creating seed with a mnemonic
var seed_normal="anmol is studying at syracuse university"
//var seed = 'a0c42a9c3ac6abf2ba6a9946ae83af18f51bf1c9fa7dacc4c92513cc4dd015834341c775dcd4c0fac73547c5662d81a9e9361a0aac604a73a321bd9103bce8af'

//Generating HD extended key pair
var hdkey = HDKey.fromMasterSeed(new Buffer(seed_normal, 'hex'));
fs.writeFileSync('./data.json', JSON.stringify(hdkey) , 'utf-8'); 

console.log("Hardened Offset for HD Key", HDKey.HARDENED_OFFSET);
//printing buffer for extended public and private key
console.log("Extended Private Key", JSON.stringify(hdkey.privateKey));
console.log("Extended Private Key", JSON.stringify(hdkey.publicKey));

//Printing few features that HD key possess
console.log("HD Key version for private",hdkey.versions.private)
console.log("HD key version for public",hdkey.versions.public);

//printing depth of hdkey
console.log("HD Key depth is",hdkey.depth) // prints 0 as the key are extended parent keys and at level 0

//printing parent fingerprint
console.log("HD key fingerprint is", hdkey.parentFingerprint) // prints 0 as it doesn't have any parent key to it

console.log("HD key identifier", hdkey.identifier.toString('hex'))
//there are many other attributes as well which we will discuss for the derived keys
var path ='m/0' //Computing child derived key at index 0 from master key we have
var childkey = hdkey.derive(path)
fs.writeFileSync('./data-child.json', JSON.stringify(childkey) , 'utf-8'); 

//printing child private key for index 0
console.log("derived child private key at index 0 is", childkey.privateExtendedKey);

//printing child public key for index 0
console.log("derived child public key at index 0 is", childkey.publicExtendedKey);

//printing few characterstics of childkey
//depth of tree at this key
console.log("derived childkey depth", childkey.depth)
console.log("derived childkey parent key print", childkey.parentFingerprint)
console.log("derived childkey index", childkey.index)
console.log("derived childkey chaincode", childkey.chainCode.toString('hex'))
console.log("derived childkey private key", childkey.privateKey.toString('hex'))
console.log("derived childkey public key", childkey.publicKey.toString('hex'))
console.log("derived childkey identifier", childkey.identifier.toString('hex'))


// You see depth 1 and index 0 proving the path as "m/0"

//Let us try to get a level 2 hardened key which shouldnt have a private key identifier as we will be creating the key through extende parent public key



//deriving child Key for Level 2 from extended parent public Key
pathNew= "m/0/2147483647"

//taken the key from JSON file created
parentPublicKey="xpub661MyMwAqRbcH2Z5RtM6ydu98YudxiUDTaBESx9VgXpURBCDdWGezitJ8ormADG6CsJPs23fLmaeLp8RJgNvFo6YJkGhpXnHusCkRhGZdqr"

console.log("parent Public Key is", parentPublicKey);
var parentPublicHDKey = HDKey.fromExtendedKey(parentPublicKey)
var childKeyLevel2 = parentPublicHDKey.derive(pathNew);
fs.writeFileSync('./data-child-level2.json', JSON.stringify(childKeyLevel2) , 'utf-8'); 

//check if private key is null
console.log("derived childkey depth", childKeyLevel2.depth)
console.log("derived childkey parent key print", childKeyLevel2.parentFingerprint)
console.log("derived childkey index", childKeyLevel2.index)
//index mentioned is 2147483647
console.log("derived childkey chaincode", childKeyLevel2.chainCode.toString('hex'))
console.log("derived childkey private key", childKeyLevel2.privateKey);
// private key is null meaning that it is a hardened key and public key cannot alone create child private keys
console.log("derived childkey public key", childKeyLevel2.publicKey.toString('hex')) 
console.log("derived childkey identifier", childKeyLevel2.identifier.toString('hex'))


//Verifying the level 2 index 214783647 extended child key could be derived from level as well
//for childKey
var path ='m/2147483647' //Computing child derived key at index 0 from master key we have
var childKeyLevel2FromLevel1 = childkey.derive(path)
fs.writeFileSync('./data-child-level2-alternate.json', JSON.stringify(childKeyLevel2FromLevel1) , 'utf-8');

//find that the publicKey in json - data-child-level2.json is same as data-child-level2-alternate.json
//This means same public key could be derived from parent as well as child level 


//Verifying a transaction signed with the HD key
childPrivKey1="xprv9ufMPXbTmCavnRkJHvmpjgh6H7DXeCiqRQVXjSHvA57v8h2zRtRUm9xs25rgAfp8E45MTd1W3B1a5XopjoemPgTmmRANQRNGRy7Em6iegRC";
childPrivKeyAlternate2= "xprv9wpaeBFtdQRvK8hUVassRDDCiYaYiyUD28wwamJ1MkqfYiAN47tacs7aoUVFhpupuHWCUeJZaApWCWWFw7YPChKnfTU1CagKhgjpsYeAiPe";
var hdkey1 = HDKey.fromExtendedKey(childPrivKey1)
var hdkey2 = HDKey.fromExtendedKey(childPrivKeyAlternate2)
console.log("hdkey1 is----", hdkey1.parentFingerprint);
console.log("hdkey2 is-----", hdkey2.parentFingerprint);

var ta = Buffer.alloc(32, 0)
var tb = Buffer.alloc(32, 8)
var a = hdkey1.sign(ta)
var b = hdkey2.sign(tb)

console.log(hdkey1.verify(ta, a));
console.log(hdkey2.verify(tb,b));

// Wiping private data off
const hdkeyModified= hdkey.wipePrivateData()
console.log("Check if private key is removed", hdkey.privateKey);

console.log(hdkeyModified.sign(Buffer.alloc(32))); // should throw an error