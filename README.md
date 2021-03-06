# Web of Needs - Privacy Preserving Reputation System

Implementation of the idea of [PrivateRide](https://petsymposium.org/2017/papers/issue2/paper09-2017-2-source.pdf) in Java 8.

[Web of Needs: Finding and cooperating with people. Protocol, not platform. Decentralized. Linked Data. Open Source.](https://github.com/researchstudio-sat/webofneeds)

## Setup

- mvn install

## How to Use

Most of the commands returns a WonMessage. Few commands have no return value - they are helper functions to make
testing easier. Helper methods are indicated with \*

**Care:** For simplification we hardcoded the IDs. See docs/alice.png bob.png carol.png and carlie.png.  
The IDs are tied to those program arguments in the images.  
To change the IDs, go to CLI.java constructor.    
The CLI Tool also prints out the Strings which need to be copied to other
instances of the CLI Tool. Which instance is described in the output.  
  
**Alice, Bob, Charlie, Carol basic protocol commands:**  
send_randomhash  
*receive_hash \<hash from other user>  
send_token_sp  
*receive_blindtoken_sp \<blindtoken>  
send_token_user  
*receive_token_user \<token other user> \<blindtoken other user>  
rate_user \<rating> \<comment> \<token other user> \<blindtoken other user>  
            
**SP protocol:**  
blindsigntoken \<token>  
rate \<rating> \<comment> \<token other user> \<blindtoken other user> \<original_hash>  
       
The Tool is supposed to act like a real implementation - so you do not have to copy and paste every single
parameter. All parameters that are used before are stored into fields in the CLI object.  


**Example between Alice, Bob and SP**:  
  
Alice:  
send_randomhash (Copy Hash - printed out by LOG.info)  
  
Bob:  
send_randomhash (Copy Hash)  
  
Alice:  
receive_hash \<hash from bob>  
send_token_sp (Copy base64 encoded Token)  
  
SP:  
blindsigntoken \<base64 encoded Token from Alice> (Copy base64 blindsignature)  
  
Alice:  
receive_blindtoken_sp \<base64 encoded blindsignature>  
send_token_user (Copy two Strings into Bobs CLI Tool)  
receive_token_user \<encoded reputation token from Bob> \<blindtoken from Bob>  
rate_user \<float 0-5> \<Comment as String> \<encoded normal token> \<blind token>  
  
SP:  
rate \<float 0-5> \<Comment as String> \<encoded normal token> \<blinded token> \<original random hash>
  
Bob:  
receive_hash \<hash from alice>  
send_token_sp (Copy base64 encoded Token)    

SP:  
blindsigntoken \<base64 encoded Token from Bob> (Copy base64 blindsignature)  
  
Bob:  
receive_blindtoken_sp \<base64 encoded blindsignature>  
send_token_user (Copy two Strings into Alice CLI Tool)  
receive_token_user \<encoded reputation token from Alice> \<blindtoken from Alice>  
rate_user \<float 0-5> \<Comment as String> \<encoded normal token> \<blind token>  
  
SP:  
rate \<float 0-5> \<Comment as String> \<encoded normal token> \<blinded token> \<original random hash>
    

## Tests

This work contains test-cases implemented with JUnit. These test classes provide an overview of how the implementation was implemented and how to use the individual classes.
We provide tests with and without sockets.

Socket implementation are the prototype for the Won network. 
The tests without sockets can be used as a library.

The test class of the CLI tool is inside src/test/java/ structure.
To test the CLI tool manually you can open up 3 terminal windows (alice, bob, SP).

## Documentation

We simulate the Reputation-Token acquiring process with plain Java Sockets. This is a simple implementation of the Idea presented in PrivateRide and the prototype for the WoN.

In WoN we use so-called bots which can perform tasks on behalf of the user. eg. acquiring ACL-Tokens or Reputation-Tokens. These tokens are based on complex computation which should be hidden from the user. The only thing the user is interested being able to create an Atom or rate another User.

### Theory: Reputation-Token

To see how the reputation token algorithm works between user, you can look at /src/test/java/WonProtocolE2ETest.java. In this test file we simulate the exchange of the reputation-tokens.
Quick overview between the Users Bob and Alice:
``
- Bob and Alice registers to the system to get a certificate (registerWithSystem)
- They generate a random number and hash them (createRandomHash)
- They exchange the random hashed number (exchangeHash)
- They sign the random hashed number from the other person with their private key (signHash)
- They create a ReputationToken which contains their certificate and the signed hashed number from the other person (createReputationToken)
- They send this RepuationToken to the SP to get a blind Signature of the bytes of that token (blindAndSign)
- They exchange the blind signed ReputationToken (exchangeReputationToken)
- They send the ReputationToken along with the original Hash to the SP to verify it (verify)

### Sockets

To simulate these Algorithms we created a prototype with plain Java Sockets /src/test/java/WonBotTest.java.
The Test-Method is considerd be a Bot of a specific side. This is side is defined in the name.
eg. runAlice means, we test Alice and test and method is Bob.
runBob means, we test Bob and the method is Alice.
runSP means, we test SP and the method is Bob or Alice. (it does not matter because Bob and Alice send the same data)

#### Blind Signature

To test blind signature over the network look at the Test-Method runSP_testBlindAndSign_valid() in WonBotTest.java
We take the side of Alice (or Bob) and create a random hashed number. We send the random hashed number to the SP. The SP blinds it and signs with her private key and returns to Alice.
In the next step we want to verify that blind signature. In the real Won we exchange the blind signature first and verify it afterwards.

#### Reputation Token

To test the exchange of Reputation Tokens look at runBob_testProtocol() in WonBotTest.java

## TODO Github-wise

- provide installation guide
- how to test
- how to use classes and functionality


