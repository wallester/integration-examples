# How to integrate with Wallester API

## Understand how JWT is generally used

Please take a look at https://jwt.io/introduction/ 

For debugging JWT requests you can use https://jwt.io/#debugger

To choose a library for JWT please see https://jwt.io

Notice that the JWT tokens are case sensitive.


## Create keys for signing and verifying JWT requests

	openssl genrsa -out example_private 2048
	openssl rsa -in example_private -pubout > example_public


## Exchange keys with Wallester

Send your public key (example_public) to Wallester and you will receive
- Wallester public key
- Wallester certificate containing the public key
- Wallester audience ID string
- your issuer ID string

Use the received information in the following steps.


## Using JWT to communicate with Wallester API

For each HTTP request, using the JWT library of your choice,
create a JWT token, and set the following fields:

- iss: your issuer ID string
- aud: Wallester audience ID string
- exp: set it into the future, for example current UTC time + allowed by Wallester maximum expiration amount
- sub: set it to "api-request"
- rbh: request body hash (see below how to calculate it)

Sign the JWT token with your private key using RS256 algorithm.

Set the JWT token in the request "Authorization" header as

	"Authorization": "Bearer <JWT token>"

Each response will contain a JWT token in the "Authorization" header as

	"Authorization": "Bearer <JWT token>"

For each response, verify the JWT token with the JWT library of your choice.

Please note, that you should also check that the "rbh" claim in the response
token is a valid hash of the response body (see below how to calculate it).


## How to calculate request/response body hash

	rbh = base64encode(sha256hash(body))


## Example Java source code

Please take a look at App.java

In this Java example we use the https://github.com/jwtk/jjwt library.

The example code uses Gradle build tool https://gradle.org/install/

### Build the example code

	make

### Run the example code

	make run

### To use openssl generated keys in Java, convert the keys to PKCS8 format:

	openssl pkcs8 -topk8 -inform PEM -outform DER -in example_private -nocrypt > example_private.pkcs8
	openssl rsa -in example_private -pubout -outform DER -out example_public.pkcs8


## Example .NET source code

Please take a look at Program.cs

The example code was developed and tested with Visual Studio Community
(https://www.visualstudio.com/vs/community/), on OSX and Windows.

You can either build and run the example from Visual Studio, or from
command line (for example, on a Mac).

### Set up the build dependencies from command line

	make deps

### Build the example code from command line

	make

### Run the example code from command line

	make run

### To use openssl generated key in .NET

	openssl req -new -x509 -nodes -sha256 -days 1100 -key example_private > example_private.cer
	openssl pkcs12 -export -in example_private.cer -inkey example_private -out example_private.pkcs12

You will need to enter a password. For the .NET sample code included in this repository,
use the password "123456".

## Example Node.js source code

Please take a look at example.js

### Install dependencies

	make install

### Run code

	make run

## Example request and response

### Request

```
POST /v1/test/ping HTTP/1.1
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJFMkMwQUI1NS1EQzM5LTQxM0ItOTRDRi00QzZGQjJDRUU2RjAiLCJzdWIiOiJhcGktcmVxdWVzdCIsImlzcyI6IjdhNGYyMTIzLTM3ZmYtNDRiMy05MDI4LTM3NDdmNGU5M2IxYyIsInJiaCI6IkN1cFgwOVh3L1dVaUM4WVdzeUpsOVJVZ0F0Ylk5Tm1WYzA1QndRR1hremM9IiwiZXhwIjoxNTA4NTA3MjUxLCJpYXQiOjE1MDg1MDcxOTF9.Zn4y5Y09BZT4KrScGYw3K2zKLjEYgfxK20ZdvRYGFgaGj9V5ZZbnY1_nJ_u5xBh4ncoyaO6eaA0YqOjZ-hPsatw4IXVPLrILg8KU3XnyEY0rYrngNmoAq7idmJQMMmIGfbpR9EEULuEiLyjcENZxF3RyVmL_Ajy8qfoTFtewAbEOLLR1wnbuNFm534DbVnlvXI9_49sEx15Q9fUzn_AjEdjfYFCBBjM8krysswckxzRtZNJP70miCYProRv6EOTQCOPIBk-qDnkzaNPEZ1PIkCyIn-yakrG-26H55m0MdjOhr9DKvUGWk_Ew7OCsMdT2ZO1NdujWE7XBt3g5GF1Kkw
User-Agent: Java/1.8.0_121
Host: localhost:8000
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
Content-Length: 18

{"message":"ping"}
```

### Response

```
HTTP/1.1 200 OK
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI3YTRmMjEyMy0zN2ZmLTQ0YjMtOTAyOC0zNzQ3ZjRlOTNiMWMiLCJleHAiOjE1MDg1MDcxOTYsImp0aSI6ImQ5MmRjYjBjLTY1Y2UtNGIwMS1iOGU3LWJkY2NlYjI5MDZmMiIsImlhdCI6MTUwODUwNzE5MSwiaXNzIjoiRTJDMEFCNTUtREMzOS00MTNCLTk0Q0YtNEM2RkIyQ0VFNkYwIiwibmJmIjoxNTA4NTA3MTkxLCJzdWIiOiJhcGktcmVxdWVzdCIsInJiaCI6IlUxNFBma1ZpTnl3aVluTjdWZEpRdUtEOFRUN1VJMy9Bc2pwenNHS3RaRnc9In0.vZyRq_1miiETTNDzIT5JJhd_Xs28wKUKlERYnOLkgWsHcLHkUdgSebRYOsbAIlhrhnOBgIzRmA6W1jBf0Dep48jOC8o7pqoRleEV_lCkrM9Xdxf-qj6LaGt8Ly_V4QUADXmQNtEoBEyReV5oiMyikUCOg2rog4c4nayquf_r8GPB68BVfB0xtaKgaBLoadX7jX4O2L0mLHdk0OA8dFmDDwScCkXdVE7MlySWGwWbjm480l15QP1bc_Kg4RiN1iqb7MI17jO5KyORZ1PR4l_0hlUem2heeXuBiwqXFNZGF1hBSLgYyS4rnZP03TjD8Jcz4EZ85nWbybVTVeoC5BSs2Q
Content-Type: application/json
X-Api-Request-Id: ec5f6d6e-bfaf-4a73-affb-407d88b0798a
Date: Fri, 20 Oct 2017 13:46:31 GMT
Content-Length: 18

{"message":"pong"}
```
