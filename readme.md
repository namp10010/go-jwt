# Simple JWT golang implementation

A simple golang implementation of JWT [JSON Web Tokens](https://jwt.io) authentication. I cannot remember if I get any part of this code from anywhere else (and google search didn't help much) so feel free to let me know so I can add credit info.

This code will demo how JWT is used to authenticate user and their resource access scopes.

For the sake of the test a new pair of keys will be generated and can be discarded.

## Development

Due to the demo nature of this code, it is understood that the whole flow has been over-simplified. Generally, the architecture would be that the functionalities are broken into multiple APIs for authenticating user and authenticating JWT.

Also in a real-life application the validation would involve a database and the validation of JWT would occur in a middleware with the JWT are inserted into a request context.

### How to run

```bash
    go run ./cmd
```

To see different outcome just uncomment the user credentials you want to test and re-run the program

```golang
    //cred := "noAccessUser:password"
    cred := "readOnlyUser:password"
    // cred := "readWriteUser:password"
```
