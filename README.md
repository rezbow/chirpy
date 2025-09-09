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

## Create User
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

## Update User
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

## Login User
* Endpoint: `/api/login`
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
  "is_chirpy_red": false,
  "token" : "jwt_token",
  "refresh_token" : "refresh_token"
}
```
## Refresh Token
* Endpoint: `/api/refresh`
* Method: POST
* Headers:
```
Authorization: Bearer <refresh_token>
```
* Response:
```
{
  "token" : "jwt_token",
}
```

## Revoke Refresh Token
* Endpoint: `/api/revoke`
* Method: POST
* Headers:
```
Authorization: Bearer <refresh_token>
```
* Response: 204 No Content

## Create Chirp
* Endpoint: `/api/chirps`
* Method: POST
* Headers:
```
Authorization: Bearer <jwt_token>
```
* Body:
```
{
  "body": "Hello, world!"
}
```
* Response:
```
{
  "id": "id",
  "body": "Hello, world!",
  "user_id" : "user_id",
  "createdAt": "createdAt",
  "updatedAt": "updatedAt"
}
```

## Delete Chirp
* Endpoint: `/api/chirps/:id`
* Method: DELETE
* Headers:
```
Authorization: Bearer <jwt_token>
```
* Response: 204 No Content

**Note** : deleting another user's chirp is not allowed and it results in a 403 Forbidden error.

## Retrieve Chirp
* Endpoint: `/api/chirps/:id`
* Method: GET
* Response:
```
{
  "id": "id",
  "body": "Hello, world!",
  "user_id" : "user_id",
  "createdAt": "createdAt",
  "updatedAt": "updatedAt"
}
```
## Retrieve Chirp Collection
* Endpoint: `/api/chirps`
* Method: GET
* Query Parameters:
```
page : number
pagSize: number
authorId: uuid
```
* Response:
```
{
  "chirps": [
    {
      "id": "id",
      "body": "Hello, world!",
      "user_id" : "user_id",
      "createdAt": "createdAt",
      "updatedAt": "updatedAt"
    },
    {
      "id": "id",
      "body": "Hello, world!",
      "user_id" : "user_id",
      "createdAt": "createdAt",
      "updatedAt": "updatedAt"
    }
  ],
  "total": 2,
  "page": 1,
  "page_size": 10,
  "total_pages": 1
}
```

# Common Error Codes
* 400 Bad Request
* 401 Unauthorized
* 404 Not Found
* 500 Internal Server Error
* 403 Forbidden
