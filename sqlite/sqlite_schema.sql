PRAGMA foreign_keys=ON;
BEGIN TRANSACTION;
CREATE TABLE credentials (
host TEXT PRIMARY KEY,
username TEXT not null,
password TEXT not null,
subscription_url TEXT,
x_auth_token TEXT,
jsonetag TEXT,
jsonreg BLOB
);

CREATE TABLE events (
host TEXT not null,
severity TEXT not null,
message TEXT not null,
resolution TEXT not null,
time integer not null,
isclearing integer DEFAULT 0,
originofcondition TEXT,
messageid TEXT not null,
category TEXT not null,
CONSTRAINT event_unique UNIQUE (host,time,originofcondition,messageid)
);
CREATE INDEX host_idx on events(host);
CREATE INDEX host_cred_idx on credentials(host);

CREATE TABLE clearing (
host TEXT not null,
originofcondition TEXT not null,
messageid TEXT not null,
time integer not null,
clearmessage TEXT not null,
CONSTRAINT fk_credentials
	FOREIGN KEY (host, originofcondition, messageid, time)
	REFERENCES events(host, originofcondition, messageid, time)
	ON DELETE CASCADE
);
COMMIT;
PRAGMA foreign_keys=on;
