ALTER TABLE app_users
    ADD COLUMN password_hash VARCHAR(100),
    ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'JOURNALIST',
    ADD COLUMN account_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE';

UPDATE app_users
SET password_hash = '$2a$10$THJZu.CZ5XEhIyYoeVSoP.78r71IsFFSh7ALtRLkUrgx.sAqOZAJS', role = 'EDITOR', account_status = 'ACTIVE'
WHERE username = 'chief_editor';

UPDATE app_users
SET password_hash = '$2a$10$JI0LXH6PXmicc1o36.zkXeWS7.leQ/n5bCQxAD7aqR6GXyow2hYZO', role = 'JOURNALIST', account_status = 'ACTIVE'
WHERE username = 'journalist_ivan';

UPDATE app_users
SET password_hash = '$2a$10$6VIDqbmN0JO.nbEHQ2DhnOY7XyPLtOMcbKHreoPBvY5O5ppA1JW5O', role = 'JOURNALIST', account_status = 'ACTIVE'
WHERE username = 'journalist_anna';

UPDATE app_users
SET password_hash = '$2a$10$JI0LXH6PXmicc1o36.zkXeWS7.leQ/n5bCQxAD7aqR6GXyow2hYZO'
WHERE password_hash IS NULL;

ALTER TABLE app_users
    ALTER COLUMN password_hash SET NOT NULL;

ALTER TABLE app_users
    ADD CONSTRAINT chk_app_users_role CHECK (role IN ('EDITOR', 'JOURNALIST')),
    ADD CONSTRAINT chk_app_users_account_status CHECK (account_status IN ('ACTIVE', 'LOCKED', 'DISABLED'));

CREATE INDEX idx_app_users_role ON app_users (role);
CREATE INDEX idx_app_users_account_status ON app_users (account_status);
