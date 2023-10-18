CREATE TABLE common_oltp.user_2fa (id SERIAL NOT NULL, user_id NUMERIC(10,0) NOT NULL, mfa_enabled BOOLEAN DEFAULT false NOT NULL, dice_enabled BOOLEAN DEFAULT false NOT NULL, created_by NUMERIC(10,0) NOT NULL, created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL DEFAULT current_timestamp, modified_by NUMERIC(10,0) NOT NULL, modified_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL DEFAULT current_timestamp, CONSTRAINT user_2fa_pk PRIMARY KEY (id), CONSTRAINT user_2fa_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user" ("user_id"), UNIQUE (user_id));
CREATE TABLE common_oltp.dice_connection (id SERIAL NOT NULL, user_id NUMERIC(10,0) NOT NULL, connection CHARACTER VARYING(50) NOT NULL, accepted BOOLEAN DEFAULT false NOT NULL, created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL DEFAULT current_timestamp, CONSTRAINT dice_connection_pk PRIMARY KEY (id), CONSTRAINT dice_connection_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user" ("user_id"), UNIQUE (user_id));
CREATE TABLE common_oltp.user_otp_email (id SERIAL NOT NULL, user_id NUMERIC(10,0) NOT NULL, mode SMALLINT NOT NULL, otp CHARACTER VARYING(6) NOT NULL, expire_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL, resend BOOLEAN default FALSE NOT NULL, fail_count SMALLINT NOT NULL DEFAULT 0, CONSTRAINT user_otp_email_pk PRIMARY KEY (id), CONSTRAINT user_otp_email_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user" ("user_id"), UNIQUE (user_id, mode));

ALTER TABLE common_oltp.dice_connection ADD COLUMN job_id CHARACTER VARYING(50), ADD COLUMN short_url CHARACTER VARYING(100), ADD COLUMN con_created_at TIMESTAMP(6) WITHOUT TIME ZONE;

UPDATE common_oltp.dice_connection SET job_id='0', con_created_at=created_at;

ALTER TABLE common_oltp.dice_connection ALTER COLUMN job_id SET NOT NULL;
ALTER TABLE common_oltp.dice_connection ALTER COLUMN connection SET NULL;

CREATE INDEX dice_connection_job_id_idx ON common_oltp.dice_connection (job_id);
CREATE INDEX dice_connection_connection_idx ON common_oltp.dice_connection (connection);

DELETE FROM common_oltp.dice_connection WHERE user_id IN (SELECT user_id from user_2fa WHERE dice_enabled='false');