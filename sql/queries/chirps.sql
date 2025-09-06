-- name: CreateChirp :one
INSERT INTO chirps (body, user_id)
VALUES ($1, $2)
RETURNING *;

-- name: DeleteChirps :exec
DELETE FROM chirps;

-- name: GetChirp :one
SELECT * FROM chirps WHERE id = $1;

-- name: GetChirps :many
SELECT * FROM chirps ORDER BY created_at DESC;
