# Introduction
chirpy is a twitter-like rest api for sharing your thoughts and opinions with others.

# Authentication
chirpy uses JWT tokens for authentication. Users can register and login to create and share chirps. For creating a user
send a POST request to `/api/users` endpoint with the following body:
```
{
  "email": "email",
  "password": "password"
}
```
use `/api/login` endpoint to generate a JWT token. Use the token in the `Authorization` header for subsequent requests.
For example:
```
curl -X POST -H "Content-Type: application/json" -d '{"email": "email", "password": "password"}' http://localhost:8080/api/login
```
and then use the jwt token for subsequent requests.
```
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"body": "Hello, world!"}' http://localhost:8080/api/chirps
```

# Endpoints

1. Create User
* Endpoint: `/api/users`
* Method: POST
* Body:
```
{
  "email": "email",
  "password": "password"
}
```
* Response:
```
{
  "id": "id",
  "email": "email",
  "createdAt": "createdAt",
  "updatedAt": "updatedAt"
  "is_chirpy_red": false
}
```

2. Update User
* Endpoint: `/api/users/`
* Method: PUT
* Headers:
```
Authorization: Bearer <jwt_token>
```
* Body:
```
{
  "email": "email",
  "password": "password"
}
```
* Response:
```
{
  "id": "id",
  "email": "email",
  "createdAt": "createdAt",
  "updatedAt": "updatedAt"
  "is_chirpy_red": false
}
```
