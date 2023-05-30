### Google OAuth using Auth0 and Golang 

Implementation of sign in using Google OAuth using Auth0 platform.

### Install dependencies

```
$ go mod install
```


### Before running

1. Create an web app in Auth0 portal and fetch values Dashboard > Application > Create application > Select "Regular Web Application" > Create

2. Add callback URL, Logout URl, and Allowed origins in settings: Application > You Application > Settings
```
Callback URL: http://localhost:9090/callback
Logout URL: http://localhost:9090
Allowed Origin: http://localhost:9090
```

Save changes

2. export secrets as environment variables as follows

```
 export AUTH0_DOMAIN='YOUR VALUE HERE';
 export AUTH0_CLIENT_ID='YOUR VALUE HERE';
 export AUTH0_CLIENT_SECRET='YOUR VALUE HERE';
 export AUTH0_CALLBACK_URL='YOUR VALUE HERE';
```

Note: If you add a space in front of the shell command, it will not be stored in bash history
### Run

```
$ go run *.go
```

### Accessing website

Here: [http://localhost:9090](http://localhost:9090)
