### Auth0 golang

Implementation of google oauth using Auth0

### Install dependencies

```
$ go install
```


### Before running

1. Create an web app in Auth0 portal and fetch values Dashboard > Application > Create application > Select "Regular Web Application" > Create

2. Add callback URL in settings Settings > Allowed callback URls `http://localhost:9090/callback` and Allowed origins as `http://localhost:9090` > Save changes

2. export secrets as environment variables as follows

```
export AUTH0_DOMAIN='YOUR VALUE HERE';
export AUTH0_CLIENT_ID='YOUR VALUE HERE';
export AUTH0_CLIENT_SECRET='YOUR VALUE HERE';
export AUTH0_CALLBACK_URL='YOUR VALUE HERE';
```
### Run

```
$ go run *.go
```

### Accessing website

Here: [http://localhost:9090](http://localhost:9090)