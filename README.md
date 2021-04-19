# Programming Assignment 2 - Secure File Transfer
## Pair Details:
- Lau Yu Hui, 1004410
- Tan Jing Heng Darryl, 1004152
## How to Run:
NOTE - We used java version 15.0.2  
1. cd to each of the 'Client' and 'Server'.
2. run 'java ./ServerCP1.java' and 'java ./ClientCP1.java' (can run CP2, just change the filename)
3. Follow the prompts in the programs to change port number or address
4. After connection and the checking of both server and client is live will be automatic. You just need to enter the password in the client side: "csebestmod". 
5. After server authenticate, then you can start sending data. Ensure that the files are in the client folder already before sending.
## Things to note for PacketTypes:
### Client
>- 33 : File transfer   successful
>- 55 : Server rejected client connection
>- 88 : Server accepted client connection
>- 111 : Password is correct
>- 222 : Password is wrong
### Server
>- -44: Authentication
>- 0 : Get FileName  
>- 1 : Get Packets  
>- 22 : Recieve Session Key
>- 44 : End client connection
>- 55 : Client say server is fake  
>- 88 : Client say sever is real