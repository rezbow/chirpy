-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    uuid_generate_v4(),
    now(),
    now(),
    $1
)
RETURNING *;

-- name: DeleteUsers :exec
DELETE FROM users;
